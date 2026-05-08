from awslabs.aws_transform_mcp_server.transform_api_client import AuthConflict


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
