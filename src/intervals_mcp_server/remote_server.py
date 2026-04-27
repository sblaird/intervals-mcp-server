"""Authenticated SSE entrypoint for hosting the Intervals.icu MCP server remotely.

Single-user OAuth 2.0 + Dynamic Client Registration. Auto-approves the
authorization step (since the only intended user is the deployer) and stores
all state in memory. claude.ai re-runs the OAuth flow automatically if state
is lost on container restart.
"""

import logging
import os
import secrets
import time
from typing import Any

import uvicorn
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    ProviderTokenVerifier,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.server.auth.settings import (
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl

import intervals_mcp_server.server  # noqa: F401  # registers all @mcp.tool() handlers
from intervals_mcp_server.config import get_config
from intervals_mcp_server.mcp_instance import mcp
from intervals_mcp_server.utils.validation import validate_athlete_id

logger = logging.getLogger("intervals_icu_mcp_server.remote")


ACCESS_TOKEN_TTL = 3600
REFRESH_TOKEN_TTL = 30 * 24 * 3600
AUTHORIZATION_CODE_TTL = 300


class SingleUserOAuthProvider(OAuthAuthorizationServerProvider):
    """In-memory OAuth provider that auto-approves authorization for the deployer.

    There is no consent UI: this server is single-tenant, deployed for personal
    use, and the only effective trust boundary is the secret-laden environment
    of the Cloud Run revision. Any client that completes Dynamic Client
    Registration is treated as authorized.
    """

    def __init__(self) -> None:
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._codes: dict[str, AuthorizationCode] = {}
        self._access_tokens: dict[str, AccessToken] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}
        self._refresh_to_access: dict[str, str] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._clients[client_info.client_id] = client_info

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        code = secrets.token_urlsafe(32)
        self._codes[code] = AuthorizationCode(
            code=code,
            scopes=params.scopes or [],
            expires_at=time.time() + AUTHORIZATION_CODE_TTL,
            client_id=client.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
        )
        return construct_redirect_uri(
            str(params.redirect_uri),
            code=code,
            state=params.state,
        )

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        record = self._codes.get(authorization_code)
        if record is None or record.client_id != client.client_id:
            return None
        if record.expires_at < time.time():
            self._codes.pop(authorization_code, None)
            return None
        return record

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        self._codes.pop(authorization_code.code, None)
        return self._issue_token_pair(client.client_id, authorization_code.scopes, authorization_code.resource)

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        record = self._refresh_tokens.get(refresh_token)
        if record is None or record.client_id != client.client_id:
            return None
        if record.expires_at is not None and record.expires_at < int(time.time()):
            self._refresh_tokens.pop(refresh_token, None)
            return None
        return record

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        old_access = self._refresh_to_access.pop(refresh_token.token, None)
        if old_access:
            self._access_tokens.pop(old_access, None)
        self._refresh_tokens.pop(refresh_token.token, None)
        return self._issue_token_pair(
            client.client_id,
            scopes or refresh_token.scopes,
            None,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        record = self._access_tokens.get(token)
        if record is None:
            return None
        if record.expires_at is not None and record.expires_at < int(time.time()):
            self._access_tokens.pop(token, None)
            return None
        return record

    async def revoke_token(self, token: Any) -> None:
        if isinstance(token, AccessToken):
            self._access_tokens.pop(token.token, None)
        elif isinstance(token, RefreshToken):
            self._refresh_tokens.pop(token.token, None)
            associated = self._refresh_to_access.pop(token.token, None)
            if associated:
                self._access_tokens.pop(associated, None)

    def _issue_token_pair(
        self,
        client_id: str,
        scopes: list[str],
        resource: str | None,
    ) -> OAuthToken:
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        now = int(time.time())
        self._access_tokens[access_token] = AccessToken(
            token=access_token,
            client_id=client_id,
            scopes=scopes,
            expires_at=now + ACCESS_TOKEN_TTL,
            resource=resource,
        )
        self._refresh_tokens[refresh_token] = RefreshToken(
            token=refresh_token,
            client_id=client_id,
            scopes=scopes,
            expires_at=now + REFRESH_TOKEN_TTL,
        )
        self._refresh_to_access[refresh_token] = access_token
        return OAuthToken(
            access_token=access_token,
            token_type="bearer",
            expires_in=ACCESS_TOKEN_TTL,
            refresh_token=refresh_token,
            scope=" ".join(scopes) if scopes else None,
        )


def build_app(server_url: str):
    provider = SingleUserOAuthProvider()

    # Cloud Run's Host header is the dynamic *.run.app URL — defeats DNS-rebinding
    # protection, which is meant for localhost servers.
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    )

    issuer = AnyHttpUrl(server_url)
    mcp.settings.auth = AuthSettings(
        issuer_url=issuer,
        resource_server_url=issuer,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["mcp"],
            default_scopes=["mcp"],
        ),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=["mcp"],
    )
    # FastMCP wires these from constructor args; we set them post-hoc to avoid
    # rebuilding the instance and re-registering every @mcp.tool().
    mcp._auth_server_provider = provider  # type: ignore[attr-defined]
    mcp._token_verifier = ProviderTokenVerifier(provider)  # type: ignore[attr-defined]

    return mcp.sse_app()


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    config = get_config()
    validate_athlete_id(config.athlete_id)

    server_url = os.getenv("MCP_SERVER_URL", "").rstrip("/")
    if not server_url:
        raise RuntimeError("MCP_SERVER_URL must be set to the public HTTPS URL of this service")

    app = build_app(server_url)

    port = int(os.getenv("PORT", "8080"))
    host = os.getenv("HOST", "0.0.0.0")
    logger.info("Starting OAuth-protected SSE MCP server on %s:%s (issuer=%s)", host, port, server_url)
    uvicorn.run(app, host=host, port=port, log_level=os.getenv("LOG_LEVEL", "info").lower())


if __name__ == "__main__":
    main()
