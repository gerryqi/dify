"""
Tests for FeishuSSOService — pure mock-based, no Dify model imports.

All Dify dependencies are patched at the module level so the test file
can be collected and run without a full Dify dependency tree.
"""

import json
import sys
from unittest.mock import MagicMock, patch

import pytest

# ── Patch all Dify infrastructure modules before importing our service ──────
sys.modules["jwt"] = MagicMock()
sys.modules["flask_sqlalchemy"] = MagicMock()
sys.modules["sqlalchemy"] = MagicMock()
sys.modules["sqlalchemy.orm"] = MagicMock()

sys.modules["models"] = MagicMock()
sys.modules["models.account"] = MagicMock()
sys.modules["models.base"] = MagicMock()
sys.modules["models.engine"] = MagicMock()
sys.modules["models.model"] = MagicMock()
sys.modules["models.enums"] = MagicMock()
sys.modules["models.types"] = MagicMock()
sys.modules["models.utils"] = MagicMock()

sys.modules["extensions.ext_database"] = MagicMock()
sys.modules["extensions.ext_redis"] = MagicMock()

sys.modules["configs"] = MagicMock()
sys.modules["configs.dify_config"] = MagicMock()

sys.modules["libs.passport"] = MagicMock()
sys.modules["libs.datetime_utils"] = MagicMock()

sys.modules["core.helper.trace_id_helper"] = MagicMock()

# Now safe to import our service
from services.feishu_sso_service import FeishuSSOService


class TestFeishuSSOService:
    """Tests for FeishuSSOService OAuth2 flow."""

    # ── is_enabled ───────────────────────────────────────────────────────────

    def test_is_enabled_true(self):
        with patch.object(FeishuSSOService, "is_enabled", return_value=True):
            assert FeishuSSOService.is_enabled()

    def test_is_enabled_false(self):
        with patch.object(FeishuSSOService, "is_enabled", return_value=False):
            assert not FeishuSSOService.is_enabled()

    # ── authorize URL ───────────────────────────────────────────────────────

    def test_get_authorization_url_has_required_params(self):
        redis_setex = MagicMock()
        with patch("extensions.ext_redis.redis_client.setex", redis_setex):
            # Patch the *class reference* that the static method reads:
            with patch.object(FeishuSSOService, "AUTHORIZE_URL", "https://open.feishu.cn/open-apis/authen/v1/index"):
                url = FeishuSSOService.get_authorization_url("my-app", "https://example.com/redirect")

        assert "app_id=" in url
        assert "redirect_uri=" in url
        assert "state=" in url
        assert redis_setex.called
        saved = json.loads(redis_setex.call_args[0][2])
        assert saved["app_code"] == "my-app"

    # ── state verify ────────────────────────────────────────────────────────

    def test_verify_and_consume_state_valid(self):
        redis_get = MagicMock(return_value=b'{"app_code":"a","redirect_url":"r"}')
        redis_del = MagicMock()
        with (
            patch("extensions.ext_redis.redis_client.get", redis_get),
            patch("extensions.ext_redis.redis_client.delete", redis_del),
        ):
            result = FeishuSSOService.verify_and_consume_state("s1")
        assert result == {"app_code": "a", "redirect_url": "r"}
        redis_del.assert_called_once()

    def test_verify_and_consume_state_expired(self):
        with patch("extensions.ext_redis.redis_client.get", return_value=None):
            assert FeishuSSOService.verify_and_consume_state("x") is None

    def test_verify_and_consume_state_bad_json(self):
        with patch("extensions.ext_redis.redis_client.get", return_value=b"not-json"):
            assert FeishuSSOService.verify_and_consume_state("x") is None

    # ── access token ────────────────────────────────────────────────────────

    @patch("httpx.post")
    def test_get_access_token_ok(self, mp):
        mp.return_value.json.return_value = {"code": 0, "data": {"access_token": "t1"}}
        with patch.object(FeishuSSOService, "_get_tenant_access_token", return_value="tt"):
            r = FeishuSSOService.get_access_token("c")
        assert r["access_token"] == "t1"

    @patch("httpx.post")
    def test_get_access_token_fail(self, mp):
        mp.return_value.json.return_value = {"code": 1, "msg": "bad"}
        with (
            patch.object(FeishuSSOService, "_get_tenant_access_token", return_value="tt"),
            pytest.raises(ValueError, match="Failed to get Feishu access token"),
        ):
            FeishuSSOService.get_access_token("c")

    # ── user info ───────────────────────────────────────────────────────────

    @patch("httpx.get")
    def test_get_user_info_ok(self, mp):
        mp.return_value.json.return_value = {"code": 0, "data": {"name": "张三", "union_id": "u1"}}
        r = FeishuSSOService.get_user_info("t")
        assert r["name"] == "张三"
        assert r["union_id"] == "u1"

    @patch("httpx.get")
    def test_get_user_info_fail(self, mp):
        mp.return_value.json.return_value = {"code": 9, "msg": "err"}
        with pytest.raises(ValueError, match="Failed to get Feishu user info"):
            FeishuSSOService.get_user_info("t")

    # ── tenant token ────────────────────────────────────────────────────────

    @patch("httpx.post")
    def test_tenant_token_ok(self, mp):
        mp.return_value.json.return_value = {"code": 0, "tenant_access_token": "tt1"}
        with (
            # Make Redis cache miss so we test the actual API call
            patch("extensions.ext_redis.redis_client.get", return_value=None),
            patch("configs.dify_config.FEISHU_APP_ID", "id"),
            patch("configs.dify_config.FEISHU_APP_SECRET", "sec"),
        ):
            assert FeishuSSOService._get_tenant_access_token() == "tt1"

    @patch("httpx.post")
    def test_tenant_token_fail(self, mp):
        mp.return_value.json.return_value = {"code": 1}
        with (
            patch("extensions.ext_redis.redis_client.get", return_value=None),
            patch("configs.dify_config.FEISHU_APP_ID", "id"),
            patch("configs.dify_config.FEISHU_APP_SECRET", "sec"),
            pytest.raises(ValueError, match="Failed to get Feishu tenant access token"),
        ):
            FeishuSSOService._get_tenant_access_token()


class TestFeishuSSOEndUser:
    """Tests for EndUser creation."""

    @patch("services.feishu_sso_service.EndUser")
    def test_creates_new(self, MockEU):
        session = MagicMock()
        site_mock, app_mock = MagicMock(), MagicMock()
        site_mock.code, app_mock.id, app_mock.tenant_id = "test-app", "a1", "t1"
        session.scalar.side_effect = [None, site_mock, app_mock]

        with patch("services.feishu_sso_service.db.session", session):
            eu = FeishuSSOService.create_or_get_end_user("test-app", {"union_id": "u_new", "name": "张三"})
        assert eu is not None

    @patch("services.feishu_sso_service.EndUser")
    def test_reuses_existing(self, MockEU):
        existing = MagicMock()
        existing.id, existing.session_id = "eu1", "feishu:u_existing"
        session = MagicMock()
        session.scalar.return_value = existing

        with patch("services.feishu_sso_service.db.session", session):
            eu = FeishuSSOService.create_or_get_end_user("app", {"union_id": "u_existing", "name": "Li"})
        assert eu.id == "eu1"


class TestFeishuSSOPassport:
    def test_issue_passport_token(self):
        eu = MagicMock()
        eu.id = "eu1"
        mp = MagicMock()
        mp.issue.return_value = "jwt:xxx"
        with patch("services.feishu_sso_service.PassportService", return_value=mp):
            t = FeishuSSOService.issue_passport_token(eu, "u1")
        assert t == "jwt:xxx"
        assert mp.issue.call_args[0][0]["end_user_id"] == "eu1"
        assert mp.issue.call_args[0][0]["token_source"] == "feishu_sso"
