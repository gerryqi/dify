"""
Feishu SSO controller for WebApp share application login.

This module provides OAuth2 SSO endpoints for Feishu (Lark) authentication.
It is a community extension and does NOT depend on any enterprise features.

Endpoints:
  POST /web-api/sso/feishu/app-login → Exchange Feishu code for passport (no login page)
  GET  /web-api/sso/feishu/login     → Generate Feishu OAuth URL
  GET  /web-api/sso/feishu/callback  → Handle Feishu OAuth callback
"""

import logging
from urllib.parse import urlencode

from flask import redirect, request
from flask_restx import Resource
from werkzeug.exceptions import BadRequest

from configs import dify_config
from controllers.web import web_ns
from services.feishu_sso_service import FeishuSSOService

logger = logging.getLogger(__name__)


@web_ns.route("/sso/feishu/app-login")
class FeishuAppLogin(Resource):
    """Feishu workplace auto-login: code → passport, no login page needed."""

    def post(self):
        """Exchange Feishu auth code for passport token.

        Request body (JSON):
            code (str): Authorization code from Feishu workplace
            app_code (str): The WebApp share code

        Returns:
            JSON with 'passport' and 'end_user_id'
        """
        if not FeishuSSOService.is_enabled():
            raise BadRequest("Feishu SSO is not enabled.")

        body = request.get_json(silent=True) or {}
        code = body.get("code")
        app_code = body.get("app_code")
        if not code or not app_code:
            raise BadRequest("Both 'code' and 'app_code' are required.")

        try:
            # Exchange code for access token → user info → EndUser → passport
            token_data = FeishuSSOService.get_access_token(code)
            user_info = FeishuSSOService.get_user_info(token_data["access_token"])
            end_user = FeishuSSOService.create_or_get_end_user(app_code, user_info)
            passport = FeishuSSOService.issue_passport_token(end_user, user_info["union_id"])
            return {"passport": passport, "end_user_id": end_user.id}
        except Exception as e:
            logger.exception("Feishu app login failed")
            return {"error": str(e)}, 400


@web_ns.route("/sso/feishu/login")
class FeishuSSOLogin(Resource):
    """Generate Feishu OAuth2 authorization URL (for browser login page button)."""

    def get(self):
        """Generate Feishu authorization URL.

        Query parameters:
            app_code (str): The WebApp share code
            redirect_url (str): URL to redirect after Feishu authentication

        Returns:
            JSON with 'url' containing the Feishu authorization URL
        """
        if not FeishuSSOService.is_enabled():
            raise BadRequest("Feishu SSO is not enabled. Set FEISHU_SSO_ENABLED=true in your .env file.")

        app_code = request.args.get("app_code")
        redirect_url = request.args.get("redirect_url")
        if not app_code or not redirect_url:
            raise BadRequest("Both 'app_code' and 'redirect_url' query parameters are required.")

        auth_url = FeishuSSOService.get_authorization_url(app_code, redirect_url)
        return {"url": auth_url}


@web_ns.route("/sso/feishu/callback")
class FeishuSSOCallback(Resource):
    """Handle Feishu OAuth callback (for browser login flow)."""

    def get(self):
        """Handle Feishu OAuth2 callback.

        Query parameters (from Feishu):
            code (str): Authorization code from Feishu
            state (str): CSRF state parameter
        """
        code = request.args.get("code")
        state = request.args.get("state")
        if not code or not state:
            raise BadRequest("Both 'code' and 'state' query parameters are required.")

        state_data = FeishuSSOService.verify_and_consume_state(state)
        if not state_data:
            raise BadRequest("Invalid or expired state parameter. Please try logging in again.")

        app_code = state_data["app_code"]
        redirect_url = state_data["redirect_url"]

        try:
            token_data = FeishuSSOService.get_access_token(code)
            user_info = FeishuSSOService.get_user_info(token_data["access_token"])
            end_user = FeishuSSOService.create_or_get_end_user(app_code, user_info)
            passport = FeishuSSOService.issue_passport_token(end_user, user_info["union_id"])

            params = urlencode({
                "passport": passport,
                "app_code": app_code,
                "redirect_url": redirect_url,
            })
            return redirect(f"{dify_config.CONSOLE_WEB_URL}/webapp-signin/feishu-callback?{params}")

        except Exception as e:
            logger.exception("Feishu SSO callback failed")
            return redirect(
                f"{dify_config.CONSOLE_WEB_URL}/webapp-signin"
                f"?error=sso_failed&message={str(e)}"
            )
