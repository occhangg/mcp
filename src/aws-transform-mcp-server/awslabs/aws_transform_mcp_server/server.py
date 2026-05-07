# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Entry point for the AWS Transform MCP server.

Creates a FastMCP instance with full guidance instructions and registers
all tool handlers.
"""

import argparse
import asyncio
import os
import sys
from awslabs.aws_transform_mcp_server.aws_helper import AwsHelper
from awslabs.aws_transform_mcp_server.config_store import (
    derive_fes_endpoint,
    extract_region_from_origin,
    load_persisted_config,
    set_sigv4_fes_available,
    set_sigv4_profile,
    set_sigv4_profiles,
)
from awslabs.aws_transform_mcp_server.consts import (
    FES_REGIONS,
    PROFILE_DISCOVERY_TIMEOUT_SECONDS,
)
from awslabs.aws_transform_mcp_server.fes_client import call_fes_direct_sigv4
from awslabs.aws_transform_mcp_server.tools.adaptive_poll import AdaptivePollHandler
from awslabs.aws_transform_mcp_server.tools.artifact import ArtifactHandler
from awslabs.aws_transform_mcp_server.tools.chat import ChatHandler
from awslabs.aws_transform_mcp_server.tools.collaborator import CollaboratorHandler
from awslabs.aws_transform_mcp_server.tools.configure import ConfigureHandler
from awslabs.aws_transform_mcp_server.tools.connector import ConnectorHandler
from awslabs.aws_transform_mcp_server.tools.get_resource import GetResourceHandler
from awslabs.aws_transform_mcp_server.tools.hitl import HitlHandler
from awslabs.aws_transform_mcp_server.tools.job import JobHandler
from awslabs.aws_transform_mcp_server.tools.job_status import JobStatusHandler
from awslabs.aws_transform_mcp_server.tools.list_resources import ListResourcesHandler
from awslabs.aws_transform_mcp_server.tools.load_instructions import LoadInstructionsHandler
from awslabs.aws_transform_mcp_server.tools.workspace import WorkspaceHandler
from loguru import logger
from mcp.server.fastmcp import FastMCP
from pathlib import Path


# ---------------------------------------------------------------------------
# Instructions — sent once during MCP initialization.  Contains cross-tool
# workflows, behavioral constraints, and capability hints only.  Individual
# tool behavior belongs in each tool's description, not here.
# ---------------------------------------------------------------------------

INSTRUCTIONS = """AWS Transform MCP Server — manage workspaces, jobs, tasks, connectors, artifacts, and agents.

# Authentication

Three auth methods (any ONE is sufficient):

1. **SigV4** (zero-config, auto-detected at startup) → if the user's AWS profile
   has valid credentials and their AWS Transform profile has been enabled
   (via the AWS Transform console settings page), all tools work automatically
   without calling `configure`. The user sets `AWS_PROFILE` and `AWS_REGION`
   in their MCP client config env block.
2. **SSO** (explicit) → run `configure` with authMode "sso". Opens a browser for
   IAM Identity Center login. Requires startUrl and idcRegion from the user.
3. **Cookie** (explicit) → run `configure` with authMode "cookie". Uses an
   existing browser session. Requires origin URL and session cookie from the user.

If `get_status` shows a valid connection (any method), do NOT call `configure`.

- `configure` and `get_status` always work without auth.
- `get_status` shows which auth method is active and whether the connection is healthy.
- `accept_connector` requires AWS credentials (for STS + TCP calls).

# Tool Selection
- **Job status / progress** → `get_job_status` (concise assistant summary by default,
  pass `detailed=true` for full raw data).
- Chat with the Transform assistant → `send_message`
- Browse collections → `list_resources`
- Fetch a single resource with full details → `get_resource`
- Check connection health → `get_status`

# Workflows

## Before working on any job

Call `load_instructions` with workspaceId and jobId first. Other tools return
INSTRUCTIONS_REQUIRED if this is skipped.

## HITL task handling

1. `get_resource(resource="task")` — fetch task details, agent artifact, `_outputSchema`, `_responseTemplate`, `_responseHint`.
2. Present task details and artifact content to the user.
3. Wait for the user's explicit decision — do NOT proceed without it.
4. `complete_task` with the user-confirmed response.

NEVER auto-submit. Never guess response content — use `_outputSchema` and
`_responseTemplate`. For file uploads: `upload_artifact` first, then include
`artifactId`. If `agentArtifactContent` is `{}`, check worklogs — the agent
may still be generating.

# Error Recovery

- `NOT_CONFIGURED` → ask the user which auth method they prefer:
  (1) SigV4: set AWS_PROFILE + AWS_REGION in MCP client env and restart,
  (2) SSO: run `configure` with authMode "sso",
  (3) Cookie: run `configure` with authMode "cookie".
- AWS credential errors → Set `AWS_PROFILE` in your MCP client config env
  block and restart. Use `get_status` to verify credentials are working.
- `INSTRUCTIONS_REQUIRED` → run `load_instructions` for the job.
- Auth errors (401/403) on any tool → run `get_status` to diagnose.
- When uncertain about parameter values, ask the user — do not guess.

# Constraints

- MUST NOT delete workspaces or jobs without explicit user confirmation.
"""


def create_server() -> FastMCP:
    """Create and return a configured FastMCP server instance.

    Separated from main() for testability.
    """
    return FastMCP(
        'awslabs.aws-transform-mcp-server',
        instructions=INSTRUCTIONS,
        dependencies=['boto3', 'botocore[crt]', 'pydantic', 'loguru', 'httpx'],
    )


def _register_handlers(mcp: FastMCP) -> None:
    """Import and instantiate all tool handler classes on *mcp*.

    All tools are registered at startup regardless of auth state.
    Auth is checked at call time — tools return NOT_CONFIGURED with a
    suggestedAction if auth is missing.
    """
    ConfigureHandler(mcp)
    WorkspaceHandler(mcp)
    JobHandler(mcp)
    HitlHandler(mcp)
    ArtifactHandler(mcp)
    ChatHandler(mcp)
    ConnectorHandler(mcp)
    ListResourcesHandler(mcp)
    GetResourceHandler(mcp)
    CollaboratorHandler(mcp)
    LoadInstructionsHandler(mcp)
    JobStatusHandler(mcp)
    AdaptivePollHandler(mcp)


async def _startup() -> None:
    """Load persisted config and probe SigV4 FES if needed."""
    loaded = await load_persisted_config()
    if not loaded:
        await _probe_sigv4_fes()


async def _probe_sigv4_fes() -> None:
    """Probe SigV4 FES auth and discover profiles at startup.

    Fans out ListAvailableProfiles across all FES regions with SigV4 signing.
    If exactly one profile is found, auto-selects it (zero-config).
    If multiple profiles are found, stores them for deferred user selection.
    If no profiles or all regions fail, disables SigV4 FES.
    """
    import os as _os
    logger.info(
        'SigV4 FES probe starting (code version: profile-discovery), AWS_PROFILE={}, AWS_REGION={}',
        _os.environ.get('AWS_PROFILE'),
        _os.environ.get('AWS_REGION'),
    )
    session = AwsHelper.create_session()
    try:
        credentials = session.get_credentials()
    except Exception as exc:
        logger.info('AWS credential resolution failed, skipping SigV4 FES probe: {}', exc)
        set_sigv4_fes_available(False)
        return
    if credentials is None:
        logger.info('No AWS credentials found, skipping SigV4 FES probe')
        set_sigv4_fes_available(False)
        return

    logger.info('SigV4 FES probe: credentials found, starting profile discovery')
    profiles = await _discover_sigv4_profiles()

    if len(profiles) == 0:
        set_sigv4_fes_available(False)
        logger.info('SigV4 FES probe: no profiles found, configure required')
        return

    if len(profiles) == 1:
        origin = profiles[0].get('applicationUrl', '').rstrip('/')
        region = extract_region_from_origin(origin) or profiles[0].get('_region', 'us-east-1')
        set_sigv4_profile(origin, region)
        set_sigv4_fes_available(True)
        logger.info('SigV4 FES probe succeeded — auto-selected profile in {}', region)
    else:
        set_sigv4_profiles(profiles)
        set_sigv4_fes_available(True)
        logger.info(
            'SigV4 FES probe succeeded — {} profiles found, selection required', len(profiles)
        )


async def _discover_sigv4_profiles() -> list:
    """Fan out ListAvailableProfiles via SigV4 across all FES regions."""

    async def _call_region(region: str) -> list:
        try:
            endpoint = derive_fes_endpoint(region)
            logger.info('SigV4 profile discovery: calling {} for region {}', endpoint, region)
            result = await asyncio.wait_for(
                call_fes_direct_sigv4(
                    endpoint,
                    'ListAvailableProfiles',
                    {},
                    timeout_seconds=PROFILE_DISCOVERY_TIMEOUT_SECONDS,
                    max_retries=0,
                    region=region,
                ),
                timeout=PROFILE_DISCOVERY_TIMEOUT_SECONDS,
            )
            profiles = result.get('profiles', []) if isinstance(result, dict) else []
            logger.info('SigV4 profile discovery: {} returned {} profiles', region, len(profiles))
            return [{**p, '_region': region} for p in profiles]
        except Exception as exc:
            logger.info('SigV4 profile discovery failed for {}: {}', region, exc)
            return []

    results = await asyncio.gather(*[_call_region(r) for r in FES_REGIONS])
    all_profiles: list = []
    for region_profiles in results:
        all_profiles.extend(region_profiles)
    return all_profiles


def main() -> None:
    """Entry point for the AWS Transform MCP server."""
    logger.remove()
    logger.add(sys.stderr, level=os.getenv('FASTMCP_LOG_LEVEL', 'INFO'))

    log_dir = Path.home() / '.aws-transform-mcp'
    log_dir.mkdir(parents=True, exist_ok=True)
    logger.add(log_dir / 'server.log', rotation='10 MB', retention='7 days', level='INFO')

    logger.info('AWS Transform MCP server starting (build: sigv4-profile-discovery)')

    parser = argparse.ArgumentParser(
        description='AWS Transform MCP server — manage workspaces, jobs, connectors, and tasks.',
    )
    parser.parse_args()
    asyncio.run(_startup())
    mcp = create_server()
    _register_handlers(mcp)
    mcp.run()


if __name__ == '__main__':
    main()
