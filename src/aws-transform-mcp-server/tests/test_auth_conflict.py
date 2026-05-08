import pytest
from awslabs.aws_transform_mcp_server.http_utils import HttpError
from awslabs.aws_transform_mcp_server.transform_api_client import AuthConflict
from unittest.mock import MagicMock, patch


class TestAuthConflict:  # noqa: D101
    def test_exception_stores_available_methods(self):
        exc = AuthConflict(
            failed_method='bearer',
            available_methods=['sigv4'],
            original_error='HTTP 403: Invalid request origin',
        )
        assert exc.failed_method == 'bearer'
        assert exc.available_methods == ['sigv4']
        assert exc.original_error == 'HTTP 403: Invalid request origin'
        assert 'Invalid request origin' in str(exc)


class TestCallTransformApiAuthConflict:  # noqa: D101
    @pytest.mark.asyncio
    async def test_raises_auth_conflict_on_origin_403_with_sigv4_available(self):
        """When bearer path gets 403 origin error and SigV4 is available, raise AuthConflict."""
        mock_config = MagicMock()
        mock_config.auth_mode = 'bearer'
        mock_config.bearer_token = 'token'
        mock_config.origin = 'https://tenant.transform.us-east-1.on.aws'
        mock_config.region = 'us-east-1'
        mock_config.token_expiry = 9999999999
        mock_config.refresh_token = None

        with (
            patch('awslabs.aws_transform_mcp_server.transform_api_client.config_store') as mock_cs,
            patch('awslabs.aws_transform_mcp_server.transform_api_client._create_unsigned_client'),
            patch(
                'awslabs.aws_transform_mcp_server.transform_api_client._call_boto3',
                side_effect=HttpError(
                    403, {'Message': 'Invalid request origin'}, 'HTTP 403: Invalid request origin'
                ),
            ),
        ):
            mock_cs.get_config.return_value = mock_config
            mock_cs.is_sigv4_fes_available.return_value = True

            from awslabs.aws_transform_mcp_server.transform_api_client import call_transform_api

            with pytest.raises(AuthConflict) as exc_info:
                await call_transform_api('ListWorkspaces', {})

            assert exc_info.value.failed_method == 'bearer'
            assert 'sigv4' in exc_info.value.available_methods
            assert 'Invalid request origin' in exc_info.value.original_error

    @pytest.mark.asyncio
    async def test_raises_auth_conflict_when_creds_exist_but_sigv4_not_probed(self):
        """When bearer gets 403 and sigv4 not probed but creds exist, still raise AuthConflict."""
        mock_config = MagicMock()
        mock_config.auth_mode = 'bearer'
        mock_config.bearer_token = 'token'
        mock_config.origin = 'https://tenant.transform.us-east-1.on.aws'
        mock_config.region = 'us-east-1'
        mock_config.token_expiry = 9999999999
        mock_config.refresh_token = None

        with (
            patch('awslabs.aws_transform_mcp_server.transform_api_client.config_store') as mock_cs,
            patch('awslabs.aws_transform_mcp_server.transform_api_client._create_unsigned_client'),
            patch(
                'awslabs.aws_transform_mcp_server.transform_api_client._call_boto3',
                side_effect=HttpError(
                    403, {'Message': 'Invalid request origin'}, 'HTTP 403: Invalid request origin'
                ),
            ),
        ):
            mock_cs.get_config.return_value = mock_config
            mock_cs.is_sigv4_fes_available.return_value = False

            mock_session = MagicMock()
            mock_session.get_credentials.return_value = MagicMock()

            with patch(
                'awslabs.aws_transform_mcp_server.transform_api_client.AwsHelper'
            ) as mock_helper:
                mock_helper.create_session.return_value = mock_session

                from awslabs.aws_transform_mcp_server.transform_api_client import (
                    call_transform_api,
                )

                with pytest.raises(AuthConflict) as exc_info:
                    await call_transform_api('ListWorkspaces', {})

                assert 'sigv4' in exc_info.value.available_methods

    @pytest.mark.asyncio
    async def test_raises_http_error_on_origin_403_without_creds(self):
        """When bearer gets 403 but no AWS creds exist, raise HttpError as before."""
        mock_config = MagicMock()
        mock_config.auth_mode = 'bearer'
        mock_config.bearer_token = 'token'
        mock_config.origin = 'https://tenant.transform.us-east-1.on.aws'
        mock_config.region = 'us-east-1'
        mock_config.token_expiry = 9999999999
        mock_config.refresh_token = None

        with (
            patch('awslabs.aws_transform_mcp_server.transform_api_client.config_store') as mock_cs,
            patch('awslabs.aws_transform_mcp_server.transform_api_client._create_unsigned_client'),
            patch(
                'awslabs.aws_transform_mcp_server.transform_api_client._call_boto3',
                side_effect=HttpError(
                    403, {'Message': 'Invalid request origin'}, 'HTTP 403: Invalid request origin'
                ),
            ),
        ):
            mock_cs.get_config.return_value = mock_config
            mock_cs.is_sigv4_fes_available.return_value = False

            mock_session = MagicMock()
            mock_session.get_credentials.return_value = None

            with patch(
                'awslabs.aws_transform_mcp_server.transform_api_client.AwsHelper'
            ) as mock_helper:
                mock_helper.create_session.return_value = mock_session

                from awslabs.aws_transform_mcp_server.transform_api_client import (
                    call_transform_api,
                )

                with pytest.raises(HttpError) as exc_info:
                    await call_transform_api('ListWorkspaces', {})

                assert exc_info.value.status_code == 403


class TestFailureResultAuthConflict:  # noqa: D101
    def test_returns_structured_choice_on_auth_conflict(self):
        import json
        from awslabs.aws_transform_mcp_server.tool_utils import failure_result

        exc = AuthConflict(
            failed_method='bearer',
            available_methods=['sigv4'],
            original_error='HTTP 403: Invalid request origin',
        )
        result = failure_result(exc)
        parsed = json.loads(result['content'][0]['text'])

        assert parsed['success'] is False
        assert parsed['error']['code'] == 'AUTH_CONFLICT'
        assert 'Invalid request origin' in parsed['error']['message']
        assert 'suggestedAction' in parsed['error']
        assert 'configure' in parsed['error']['suggestedAction']
        assert parsed['failedMethod'] == 'bearer'
        assert 'sigv4' in parsed['availableMethods']
        assert result['isError'] is True
