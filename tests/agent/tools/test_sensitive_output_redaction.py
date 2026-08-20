from vxis.agent.tools import skill_runner


def test_sensitive_tool_output_redacts_secrets_and_user_blobs() -> None:
    token = "token-1234567890-secret"
    output = {
        "authenticated": True,
        "method": "default_creds",
        "token": token,
        "credentials_used": {"email": "alice@example.test", "password": "alice-pass"},
        "user_info": {"email": "alice@example.test", "role": "admin"},
        "poc_http_exchange": f'Authorization: Bearer {token}\n"password":"alice-pass"',
    }

    redacted = skill_runner.redact_sensitive_output(output)

    rendered = repr(redacted)
    assert token not in rendered
    assert "alice-pass" not in rendered
    assert "alice@example.test" not in rendered
    assert redacted["authenticated"] is True
    assert redacted["method"] == "default_creds"


def test_sensitive_tool_output_redacts_common_key_variants_and_bearer_text() -> None:
    output = {
        "access_token": "access-value",
        "refresh-token": "refresh-value",
        "api_key": "api-value",
        "X-API-Key": "header-value",
        "client_secret": "client-value",
        "Set-Cookie": "session=raw-cookie",
        "nested": "request used Bearer standalone-value",
        "input_tokens": 123,
    }

    redacted = skill_runner.redact_sensitive_output(output)

    assert all(
        redacted[key] == "[redacted]"
        for key in (
            "access_token",
            "refresh-token",
            "api_key",
            "X-API-Key",
            "client_secret",
            "Set-Cookie",
        )
    )
    assert redacted["nested"] == "request used Bearer [redacted]"
    assert redacted["input_tokens"] == 123
