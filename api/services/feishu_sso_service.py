"""
Feishu (Lark) SSO Service for Dify community edition.

This module provides OAuth2 authentication flow for Feishu users accessing WebApp
shared applications. It is designed as a community extension and does NOT depend
on any enterprise features or modify any enterprise code.

Flow:
  1. Frontend requests authorization URL → user redirected to Feishu
  2. User authenticates on Feishu → Feishu redirects back with auth code
  3. Backend exchanges code for access token
  4. Backend fetches user info (name, avatar, email, open_id, union_id)
  5. Backend creates or retrieves EndUser bound to Feishu union_id
  6. Backend issues passport token → redirects frontend
"""

import json
import logging
import secrets
from typing import Any

import httpx
from sqlalchemy import select

from configs import dify_config
from extensions.ext_database import db
from extensions.ext_redis import redis_client
from libs.passport import PassportService
from models.account import Account
from models.model import App, EndUser, Site

logger = logging.getLogger(__name__)


class FeishuSSOService:
    """Feishu OAuth2 SSO authentication service for WebApp share applications."""

    # Feishu Open API endpoints
    AUTHORIZE_URL = "https://open.feishu.cn/open-apis/authen/v1/index"
    TOKEN_URL = "https://open.feishu.cn/open-apis/authen/v1/access_token"
    USER_INFO_URL = "https://open.feishu.cn/open-apis/authen/v1/user_info"
    TENANT_TOKEN_URL = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"

    # Redis key prefixes
    STATE_CACHE_PREFIX = "feishu_sso_state:"
    # 5 minutes TTL for OAuth state
    STATE_CACHE_TTL = 300

    @classmethod
    def is_enabled(cls) -> bool:
        """Check if Feishu SSO is enabled via configuration."""
        return dify_config.FEISHU_SSO_ENABLED

    @classmethod
    def get_authorization_url(cls, app_code: str, redirect_url: str) -> str:
        """Generate Feishu OAuth2 authorization URL with CSRF state parameter.

        Args:
            app_code: The WebApp share code (used as the EndUser's target app)
            redirect_url: The URL to redirect back to after authentication

        Returns:
            Full Feishu authorization URL with query parameters
        """
        state = secrets.token_urlsafe(32)
        # Store state → {app_code, redirect_url} mapping in Redis for CSRF protection
        redis_client.setex(
            f"{cls.STATE_CACHE_PREFIX}{state}",
            cls.STATE_CACHE_TTL,
            json.dumps({"app_code": app_code, "redirect_url": redirect_url}),
        )
        params = {
            "app_id": dify_config.FEISHU_APP_ID,
            "redirect_uri": dify_config.FEISHU_REDIRECT_URI,
            "state": state,
        }
        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{cls.AUTHORIZE_URL}?{query}"

    @classmethod
    def verify_and_consume_state(cls, state: str) -> dict[str, str] | None:
        """Verify the OAuth state parameter and consume it (one-time use).

        Args:
            state: The state parameter returned by Feishu callback

        Returns:
            Dict with app_code and redirect_url, or None if state is invalid/expired
        """
        key = f"{cls.STATE_CACHE_PREFIX}{state}"
        raw = redis_client.get(key)
        if not raw:
            return None
        redis_client.delete(key)
        try:
            data = json.loads(raw)
            if "app_code" in data and "redirect_url" in data:
                return data
        except (json.JSONDecodeError, TypeError):
            logger.exception("Failed to decode Feishu SSO state")
        return None

    @classmethod
    def _get_tenant_access_token(cls) -> str:
        """Get tenant access token for server-to-server API calls with Feishu.

        Returns:
            tenant_access_token string

        Raises:
            ValueError: If Feishu API returns an error
        """
        resp = httpx.post(
            cls.TENANT_TOKEN_URL,
            json={
                "app_id": dify_config.FEISHU_APP_ID,
                "app_secret": dify_config.FEISHU_APP_SECRET,
            },
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("code") != 0:
            raise ValueError(f"Failed to get Feishu tenant access token: code={data.get('code')}")
        return data["tenant_access_token"]

    @classmethod
    def get_access_token(cls, code: str) -> dict[str, Any]:
        """Exchange Feishu authorization code for user access token.

        Args:
            code: The authorization code from Feishu OAuth callback

        Returns:
            Dict containing access_token, refresh_token, token_type, expires_in

        Raises:
            ValueError: If Feishu API returns an error
        """
        tenant_token = cls._get_tenant_access_token()
        resp = httpx.post(
            cls.TOKEN_URL,
            headers={"Authorization": f"Bearer {tenant_token}"},
            json={
                "grant_type": "authorization_code",
                "code": code,
                "app_id": dify_config.FEISHU_APP_ID,
                "app_secret": dify_config.FEISHU_APP_SECRET,
            },
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("code") != 0:
            raise ValueError(f"Failed to get Feishu access token: code={data.get('code')}")
        return data["data"]

    @classmethod
    def get_user_info(cls, access_token: str) -> dict[str, Any]:
        """Get Feishu user information using the access token.

        Returns:
            Dict containing: name, avatar_url, avatar_thumb, avatar_middle,
            open_id, union_id, email, enterprise_email, user_id, mobile

        Raises:
            ValueError: If Feishu API returns an error
        """
        resp = httpx.get(
            cls.USER_INFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("code") != 0:
            raise ValueError(f"Failed to get Feishu user info: code={data.get('code')}")
        return data["data"]

    @classmethod
    def create_or_get_end_user(cls, app_code: str, feishu_user: dict) -> EndUser:
        """Find existing EndUser by Feishu union_id or create a new one.

        Args:
            app_code: The WebApp share code
            feishu_user: User info dict from Feishu (must contain 'union_id')

        Returns:
            Existing or newly created EndUser instance
        """
        union_id = feishu_user["union_id"]
        session_id = f"feishu:{union_id}"

        # Try to find existing EndUser by Feishu union_id
        existing = db.session.scalar(
            select(EndUser).where(EndUser.session_id == session_id)
        )
        if existing:
            logger.info("Found existing EndUser for Feishu user %s", union_id)
            return existing

        # Resolve app from app_code
        site = db.session.scalar(select(Site).where(Site.code == app_code))
        if not site:
            raise ValueError(f"Site not found for app_code: {app_code}")
        app = db.session.get(App, site.app_id)
        if not app:
            raise ValueError(f"App not found for site: {site.id}")

        name = feishu_user.get("name", "FeishuUser") or "FeishuUser"

        # Create new EndUser
        end_user = EndUser(
            tenant_id=app.tenant_id,
            app_id=app.id,
            type="browser",
            is_anonymous=False,
            session_id=session_id,
            name=name,
            external_user_id=union_id,
        )
        db.session.add(end_user)
        db.session.commit()

        logger.info("Created new EndUser for Feishu user %s (app=%s)", union_id, app_code)
        return end_user

    @classmethod
    def issue_passport_token(cls, end_user: EndUser, feishu_union_id: str) -> str:
        """Issue a passport (JWT) token for the given EndUser.

        Args:
            end_user: The EndUser to issue a token for
            feishu_union_id: The Feishu user's union_id

        Returns:
            JWT passport token string
        """
        passport = PassportService().issue({
            "end_user_id": end_user.id,
            "session_id": f"feishu:{feishu_union_id}",
            "token_source": "feishu_sso",
        })
        return passport
