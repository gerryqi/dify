"""
Feishu SSO controller for WebApp share application login.

This module provides OAuth2 SSO endpoints for Feishu (Lark) authentication.
It is a community extension and does NOT depend on any enterprise features.

Endpoints:
  GET /web-api/sso/feishu/login    → Generate Feishu OAuth URL
  GET /web-api/sso/feishu/callback → Handle Feishu OAuth callback
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


@web_ns.route("/sso/feishu/login")
class FeishuSSOLogin(Resource):
    """Generate Feishu OAuth2 authorization URL and return it to the frontend."""

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
    """Handle Feishu OAuth callback, create/get EndUser, and issue passport."""

    def get(self):
        """Handle Feishu OAuth2 callback.

        Query parameters (from Feishu):
            code (str): Authorization code from Feishu
            state (str): CSRF state parameter

        Process:
            1. Verify state (CSRF protection)
            2. Exchange code for access token
            3. Fetch user info from Feishu
            4. Create or get EndUser
            5. Issue passport token
            6. Redirect frontend with passport

        Returns:
            302 redirect to frontend callback page with passport token
        """
        code = request.args.get("code")
        state = request.args.get("state")
        if not code or not state:
            raise BadRequest("Both 'code' and 'state' query parameters are required.")

        # Verify state (CSRF protection)
        state_data = FeishuSSOService.verify_and_consume_state(state)
        if not state_data:
            raise BadRequest("Invalid or expired state parameter. Please try logging in again.")

        app_code = state_data["app_code"]
        redirect_url = state_data["redirect_url"]

        try:
            # Exchange authorization code for access token
            token_data = FeishuSSOService.get_access_token(code)
            access_token = token_data["access_token"]

            # Fetch user info from Feishu
            user_info = FeishuSSOService.get_user_info(access_token)

            # Create or get EndUser
            end_user = FeishuSSOService.create_or_get_end_user(app_code, user_info)

            # Issue passport token
            passport = FeishuSSOService.issue_passport_token(end_user, user_info["union_id"])

            # Redirect to frontend callback page with passport token
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
