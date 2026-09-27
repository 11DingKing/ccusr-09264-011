"""HTTP API 端到端：真实启动服务，经 HTTP 走完整流程与鉴权。"""
import base64
import json
import unittest
import urllib.error
import urllib.request

from service_09252_006.api.http_api import HttpApiServer
from service_09252_006.application.container import ApplicationContext
from tests.support import Harness


class ApiClient:
    def __init__(self, base_url: str, token: str | None = None,
                 bootstrap: str | None = None) -> None:
        self.base_url = base_url
        self.token = token
        self.bootstrap = bootstrap

    def request(self, method: str, path: str, body=None,
                idempotency_key=None, raw=False):
        url = self.base_url + path
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if self.bootstrap:
            headers["X-Bootstrap-Token"] = self.bootstrap
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                payload = resp.read()
                if raw:
                    return resp.status, payload, dict(resp.headers)
                return resp.status, json.loads(payload.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            if raw:
                return exc.code, payload, dict(exc.headers)
            try:
                return exc.code, json.loads(payload.decode("utf-8"))
            except json.JSONDecodeError:
                return exc.code, {"raw": payload.decode("utf-8")}


class HttpApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.server = HttpApiServer(
            self.h.ctx, host="127.0.0.1", port=0, bootstrap_token="boot-secret"
        )
        self.server.start()
        host, port = self.server.address
        self.base = f"http://{host}:{port}"
        self.boot = ApiClient(self.base, bootstrap="boot-secret")

    def tearDown(self) -> None:
        self.server.stop()
        self.h.close()

    def _create_user(self, user_id, roles, institution_id=None, token=None):
        status, body = self.boot.request(
            "POST", "/v1/admin/users",
            {"user_id": user_id, "roles": roles,
             "institution_id": institution_id},
        )
        self.assertEqual(status, 201, body)
        if token:
            status, body = self.boot.request(
                "POST", "/v1/admin/tokens",
                {"user_id": user_id, "token": token},
            )
            self.assertEqual(status, 201, body)
        return ApiClient(self.base, token=token)

    def test_end_to_end_over_http_with_minimal_disclosure(self) -> None:
        admin = self._create_user(
            "admin-a", ["institution_admin"], "inst-a", "tok-admin"
        )
        submitter = self._create_user(
            "sub-a", ["institution_submitter"], "inst-a", "tok-sub"
        )
        authority = self._create_user(
            "auth", ["quality_authority"], None, "tok-auth"
        )
        reviewer = self._create_user(
            "rev-1", ["reviewer"], "inst-ext", "tok-rev"
        )

        # 未认证被拒
        status, body = ApiClient(self.base).request("GET", "/v1/packages")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "permission_denied")

        # 引导端点需要 bootstrap token
        status, body = ApiClient(self.base).request(
            "POST", "/v1/admin/users",
            {"user_id": "x", "roles": [], "institution_id": None},
        )
        self.assertEqual(status, 403)

        # 接收证据
        status, mat = admin.request(
            "POST", "/v1/materials",
            {"kind": "enterprise_feedback", "title": "企业反馈",
             "sensitivity": "sensitive"},
        )
        self.assertEqual(status, 201)
        content = "敏感：企业 X 要求不具名".encode("utf-8")
        status, ver = admin.request(
            "POST", f"/v1/materials/{mat['material_id']}/versions",
            {"content_base64": base64.b64encode(content).decode("ascii"),
             "media_type": "text/plain"},
            idempotency_key="upload-1",
        )
        self.assertEqual(status, 201)
        # 幂等重放
        status, ver2 = admin.request(
            "POST", f"/v1/materials/{mat['material_id']}/versions",
            {"content_base64": base64.b64encode(content).decode("ascii")},
            idempotency_key="upload-1",
        )
        self.assertEqual(status, 201)
        self.assertEqual(ver["version_id"], ver2["version_id"])
        self.assertTrue(ver2["replayed"])

        # 组包封存
        status, pkg = admin.request("POST", "/v1/packages", {"title": "2026秋"})
        pid = pkg["package_id"]
        status, _ = admin.request(
            "POST", f"/v1/packages/{pid}/entries",
            {"version_id": ver["version_id"]},
        )
        self.assertEqual(status, 201)
        status, sealed = admin.request("POST", f"/v1/packages/{pid}/seal", {})
        self.assertEqual(status, 200)
        self.assertIn("manifest_fingerprint", sealed)

        # 提交人看不到敏感反馈内容
        status, view = submitter.request("GET", f"/v1/packages/{pid}")
        self.assertEqual(status, 200)
        self.assertTrue(view["entries"][0]["redacted"])
        status, resp = submitter.request(
            "GET", f"/v1/packages/{pid}/entries/{ver['version_id']}/content",
        )
        self.assertEqual(status, 403)

        # 分配评审后可见可下载
        status, req = authority.request(
            "POST", f"/v1/packages/{pid}/assignments",
            {"reviewer_id": "rev-1",
             "deadline_local_iso": "2026-09-25T18:00",
             "deadline_timezone": "Asia/Shanghai"},
        )
        self.assertEqual(status, 201)
        rid = req["request_id"]
        status, _ = reviewer.request(
            "POST", f"/v1/requests/{rid}/respond", {"accept": True}
        )
        self.assertEqual(status, 200)
        status, payload, headers = reviewer.request(
            "GET", f"/v1/packages/{pid}/entries/{ver['version_id']}/content",
            raw=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, content)
        self.assertEqual(headers["X-Content-Sha256"], ver["sha256"])

        # 评审通过并签发
        status, _ = reviewer.request(
            "POST", f"/v1/requests/{rid}/verdict",
            {"verdict": "approve", "comment": "材料齐备"},
        )
        self.assertEqual(status, 200)
        status, decision = authority.request(
            "POST", f"/v1/packages/{pid}/decision",
            {"decision": "approved", "note": "通过"},
            idempotency_key="decide-1",
        )
        self.assertEqual(status, 200)
        status, decision2 = authority.request(
            "POST", f"/v1/packages/{pid}/decision",
            {"decision": "rejected", "note": "重复请求应回放"},
            idempotency_key="decide-1",
        )
        self.assertEqual(status, 200)
        self.assertEqual(decision2["decision"], "approved")
        self.assertTrue(decision2["replayed"])

    def test_health(self) -> None:
        status, body = ApiClient(self.base).request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

    def test_cross_institution_grant_revocation_over_http(self) -> None:
        """双方确认授权 -> 跨机构可访问；撤销后新请求立即 403；旧审计仍可查。"""
        admin_a = self._create_user(
            "admin-a", ["institution_admin"], "inst-a", "tok-a"
        )
        admin_b = self._create_user(
            "admin-b", ["institution_admin"], "inst-b", "tok-b"
        )
        member_b = self._create_user(
            "mem-b", ["institution_submitter"], "inst-b", "tok-memb"
        )

        # inst-a 组包封存（大纲 + 敏感企业反馈）
        import base64 as _b64

        status, mat = admin_a.request(
            "POST", "/v1/materials",
            {"kind": "syllabus", "title": "大纲", "sensitivity": "normal"},
        )
        self.assertEqual(status, 201)
        syllabus = "大纲正文".encode("utf-8")
        status, ver = admin_a.request(
            "POST", f"/v1/materials/{mat['material_id']}/versions",
            {"content_base64": _b64.b64encode(syllabus).decode("ascii")},
        )
        self.assertEqual(status, 201)
        status, pkg = admin_a.request("POST", "/v1/packages", {"title": "包"})
        pid = pkg["package_id"]
        admin_a.request(
            "POST", f"/v1/packages/{pid}/entries",
            {"version_id": ver["version_id"]},
        )
        admin_a.request("POST", f"/v1/packages/{pid}/seal", {})

        # 授权前：inst-b 用户新请求 403
        status, body = member_b.request("GET", f"/v1/packages/{pid}")
        self.assertEqual(status, 403)

        # 授予方提议（字段范围 syllabus）
        status, grant = admin_a.request(
            "POST", "/v1/grants",
            {"recipient_institution_id": "inst-b", "field_scopes": ["syllabus"]},
        )
        self.assertEqual(status, 201, grant)
        gid = grant["grant_id"]
        self.assertEqual(grant["status"], "proposed")

        # 仅提议未确认：仍 403
        status, _ = member_b.request("GET", f"/v1/packages/{pid}")
        self.assertEqual(status, 403)

        # 接收方确认（双方确认）后可访问
        status, confirmed = admin_b.request(
            "POST", f"/v1/grants/{gid}/confirm", {}
        )
        self.assertEqual(status, 200)
        self.assertEqual(confirmed["status"], "active")
        status, view = member_b.request("GET", f"/v1/packages/{pid}")
        self.assertEqual(status, 200)
        self.assertEqual(view["via_grant"]["grant_id"], gid)
        status, payload, _ = member_b.request(
            "GET", f"/v1/packages/{pid}/entries/{ver['version_id']}/content",
            raw=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, syllabus)

        # 撤销：新请求立即拒绝
        status, revoked = admin_a.request(
            "POST", f"/v1/grants/{gid}/revoke", {"reason": "学期合作结束"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(revoked["status"], "revoked")
        self.assertIsNotNone(revoked["revoked_at"])
        status, body = member_b.request("GET", f"/v1/packages/{pid}")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "permission_denied")

        # 旧审计仍可查看：提议/确认/撤销都在
        status, audit_body = admin_b.request("GET", f"/v1/grants/{gid}/audit")
        self.assertEqual(status, 200)
        actions = [a["action"] for a in audit_body["audit"]]
        self.assertIn("grant.proposed", actions)
        self.assertIn("grant.confirmed", actions)
        self.assertIn("grant.revoked", actions)


if __name__ == "__main__":
    unittest.main()
