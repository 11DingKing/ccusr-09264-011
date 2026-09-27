"""跨机构授权：双方确认、字段范围、撤销即时生效、旧审计仍可查。"""
from __future__ import annotations

import base64
import unittest

from service_09252_006.api.http_api import HttpApiServer
from service_09252_006.domain.enums import (
    GrantStatus,
    MaterialKind,
    Role,
    Sensitivity,
)
from service_09252_006.domain.errors import (
    ConflictError,
    PermissionDeniedError,
    ValidationError,
)
from tests.flow import seal_new_package, upload_material
from tests.support import Harness
from tests.test_http_api import ApiClient


class GrantLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin_a = self.h.user(
            "admin-a", Role.INSTITUTION_ADMIN, institution_id="inst-a"
        )
        self.admin_b = self.h.user(
            "admin-b", Role.INSTITUTION_ADMIN, institution_id="inst-b"
        )
        self.admin_c = self.h.user(
            "admin-c", Role.INSTITUTION_ADMIN, institution_id="inst-c"
        )
        self.auditor = self.h.user("aud", Role.AUDITOR, institution_id=None)

    def tearDown(self) -> None:
        self.h.close()

    def _propose(self, scopes=("kind:enterprise_feedback",)):
        return self.h.ctx.grants.propose_grant(
            self.admin_a,
            receiver_institution_id="inst-b",
            field_scopes=list(scopes),
        )

    def test_propose_requires_granter_institution_admin(self) -> None:
        submitter = self.h.user(
            "sub-a", Role.INSTITUTION_SUBMITTER, institution_id="inst-a"
        )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.grants.propose_grant(
                submitter,
                receiver_institution_id="inst-b",
                field_scopes=["kind:enterprise_feedback"],
            )

    def test_cannot_grant_to_self_and_scopes_validated(self) -> None:
        with self.assertRaises(ValidationError):
            self.h.ctx.grants.propose_grant(
                self.admin_a,
                receiver_institution_id="inst-a",
                field_scopes=["kind:enterprise_feedback"],
            )
        with self.assertRaises(ValidationError):
            self.h.ctx.grants.propose_grant(
                self.admin_a,
                receiver_institution_id="inst-b",
                field_scopes=[],
            )
        with self.assertRaises(ValidationError):
            self.h.ctx.grants.propose_grant(
                self.admin_a,
                receiver_institution_id="inst-b",
                field_scopes=["bogus:scope"],
            )
        with self.assertRaises(ValidationError):
            self.h.ctx.grants.propose_grant(
                self.admin_a,
                receiver_institution_id="inst-b",
                field_scopes=["kind:not_a_kind"],
            )

    def test_propose_then_confirm_by_receiver(self) -> None:
        grant = self._propose()
        self.assertEqual(grant["status"], GrantStatus.PROPOSED.value)
        self.assertIsNone(grant["confirmed_at"])
        self.assertEqual(grant["granter_institution_id"], "inst-a")
        self.assertEqual(grant["receiver_institution_id"], "inst-b")

        # 授予方不能替接收方确认；第三方也不能
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.grants.confirm_grant(
                self.admin_a, grant_id=grant["grant_id"]
            )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.grants.confirm_grant(
                self.admin_c, grant_id=grant["grant_id"]
            )

        active = self.h.ctx.grants.confirm_grant(
            self.admin_b, grant_id=grant["grant_id"]
        )
        self.assertEqual(active["status"], GrantStatus.ACTIVE.value)
        self.assertEqual(active["confirmed_by"], "admin-b")
        self.assertIsNotNone(active["confirmed_at"])

        # 重复确认为幂等回放
        again = self.h.ctx.grants.confirm_grant(
            self.admin_b, grant_id=grant["grant_id"]
        )
        self.assertTrue(again["replayed"])

    def test_revoked_grant_cannot_be_confirmed(self) -> None:
        grant = self._propose()
        self.h.ctx.grants.revoke_grant(
            self.admin_a, grant_id=grant["grant_id"], reason="变更"
        )
        with self.assertRaises(ConflictError):
            self.h.ctx.grants.confirm_grant(
                self.admin_b, grant_id=grant["grant_id"]
            )

    def test_only_parties_may_revoke_and_revoke_is_idempotent(self) -> None:
        grant = self._propose()
        self.h.ctx.grants.confirm_grant(
            self.admin_b, grant_id=grant["grant_id"]
        )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.grants.revoke_grant(
                self.admin_c, grant_id=grant["grant_id"]
            )
        revoked = self.h.ctx.grants.revoke_grant(
            self.admin_b, grant_id=grant["grant_id"], reason="合作终止"
        )
        self.assertEqual(revoked["status"], GrantStatus.REVOKED.value)
        self.assertEqual(revoked["revoked_by"], "admin-b")
        self.assertIsNotNone(revoked["revoked_at"])
        again = self.h.ctx.grants.revoke_grant(
            self.admin_a, grant_id=grant["grant_id"]
        )
        self.assertTrue(again["replayed"])
        self.assertEqual(again["revoked_by"], "admin-b")


class GrantAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin_a = self.h.user(
            "admin-a", Role.INSTITUTION_ADMIN, institution_id="inst-a"
        )
        self.admin_b = self.h.user(
            "admin-b", Role.INSTITUTION_ADMIN, institution_id="inst-b"
        )
        self.reviewer_b = self.h.user(
            "rev-b", Role.REVIEWER, institution_id="inst-b"
        )
        self.submitter_b = self.h.user(
            "sub-b", Role.INSTITUTION_SUBMITTER, institution_id="inst-b"
        )
        self.admin_c = self.h.user(
            "admin-c", Role.INSTITUTION_ADMIN, institution_id="inst-c"
        )
        self.auditor = self.h.user("aud", Role.AUDITOR, institution_id=None)

        sealed = seal_new_package(self.h, self.admin_a)
        self.pid = sealed.package_id
        # 默认包：items[0] 大纲(normal)，items[1] 企业反馈(sensitive)
        self.normal_version = sealed.items[0].version["version_id"]
        self.sensitive_version = sealed.items[1].version["version_id"]
        self.sensitive_material = sealed.items[1].material["material_id"]

    def tearDown(self) -> None:
        self.h.close()

    def _active_grant(self, scopes, *, granter=None, receiver="inst-b"):
        granter = granter or self.admin_a
        grant = self.h.ctx.grants.propose_grant(
            granter,
            receiver_institution_id=receiver,
            field_scopes=list(scopes),
        )
        receiver_admin = self.admin_b if receiver == "inst-b" else self.admin_c
        self.h.ctx.grants.confirm_grant(
            receiver_admin, grant_id=grant["grant_id"]
        )
        return grant

    def _find(self, view, version_id):
        return next(e for e in view["entries"] if e["version_id"] == version_id)

    def test_proposed_grant_does_not_yet_authorize(self) -> None:
        self.h.ctx.grants.propose_grant(
            self.admin_a,
            receiver_institution_id="inst-b",
            field_scopes=["kind:enterprise_feedback"],
        )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.build_package_view(self.admin_b, self.pid)
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.download_entry(
                self.admin_b,
                package_id=self.pid,
                version_id=self.sensitive_version,
            )

    def test_active_kind_grant_unlocks_only_scoped_field(self) -> None:
        self._active_grant(["kind:enterprise_feedback"])

        view = self.h.ctx.packages.build_package_view(self.admin_b, self.pid)
        self.assertFalse(self._find(view, self.sensitive_version)["redacted"])
        # 大纲不在字段范围内：仍遮蔽
        self.assertTrue(self._find(view, self.normal_version)["redacted"])

        meta, data, _ = self.h.ctx.packages.download_entry(
            self.admin_b,
            package_id=self.pid,
            version_id=self.sensitive_version,
        )
        self.assertEqual(data, "敏感反馈：企业要求匿名".encode("utf-8"))
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.download_entry(
                self.admin_b,
                package_id=self.pid,
                version_id=self.normal_version,
            )

    def test_active_material_grant_scopes_to_one_material(self) -> None:
        other = upload_material(
            self.h, self.admin_a,
            kind=MaterialKind.ENTERPRISE_FEEDBACK.value,
            data="另一份敏感反馈".encode("utf-8"),
            title="反馈2",
            sensitivity=Sensitivity.SENSITIVE.value,
        )
        sealed2 = seal_new_package(
            self.h, self.admin_a, items=[other], title="第二个包"
        )
        self._active_grant([f"material:{self.sensitive_material}"])

        # 具体材料授权：本材料可见
        view = self.h.ctx.packages.build_package_view(self.admin_b, self.pid)
        self.assertFalse(self._find(view, self.sensitive_version)["redacted"])
        # 同类但另一份材料不覆盖
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.build_package_view(
                self.admin_b, sealed2.package_id
            )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.download_entry(
                self.admin_b,
                package_id=sealed2.package_id,
                version_id=other.version["version_id"],
            )

    def test_reviewer_of_receiver_institution_covered_submitter_not(self) -> None:
        self._active_grant(["kind:enterprise_feedback"])
        # 接收方机构评审人可凭授权访问
        meta, data, _ = self.h.ctx.packages.download_entry(
            self.reviewer_b,
            package_id=self.pid,
            version_id=self.sensitive_version,
        )
        self.assertEqual(
            data, "敏感反馈：企业要求匿名".encode("utf-8")
        )
        # 提交人角色不在凭授权访问的角色集合内
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.build_package_view(self.submitter_b, self.pid)

    def test_third_institution_without_grant_rejected(self) -> None:
        self._active_grant(["kind:enterprise_feedback"])
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.build_package_view(self.admin_c, self.pid)

    def test_revoke_immediately_denies_new_requests_but_history_remains(self) -> None:
        grant = self._active_grant(["kind:enterprise_feedback"])

        # 撤销前可访问，产生一条 grant.accessed 审计
        _, data_before, _ = self.h.ctx.packages.download_entry(
            self.admin_b,
            package_id=self.pid,
            version_id=self.sensitive_version,
        )
        self.assertEqual(
            data_before, "敏感反馈：企业要求匿名".encode("utf-8")
        )

        # 授予方撤销；记录撤销时间
        revoked = self.h.ctx.grants.revoke_grant(
            self.admin_a,
            grant_id=grant["grant_id"],
            reason="合作机构变更授权",
        )
        self.assertEqual(revoked["status"], GrantStatus.REVOKED.value)
        self.assertIsNotNone(revoked["revoked_at"])

        # 新请求立即拒绝（无需重启、无缓存）
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.build_package_view(self.admin_b, self.pid)
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.download_entry(
                self.admin_b,
                package_id=self.pid,
                version_id=self.sensitive_version,
            )

        # 授权记录仍可读取（撤销状态/撤销时间留痕）
        stored = self.h.ctx.grants.get_grant(self.auditor, grant["grant_id"])
        self.assertEqual(stored["status"], GrantStatus.REVOKED.value)
        self.assertEqual(stored["revoke_reason"], "合作机构变更授权")
        self.assertEqual(stored["field_scopes"], ["kind:enterprise_feedback"])

        # 旧审计仍可查看：发起/确认/访问/撤销事件全部保留
        actions = [e.action for e in self.h.repo.list_audit(limit=500)]
        for expected in (
            "grant.proposed",
            "grant.confirmed",
            "grant.accessed",
            "grant.revoked",
        ):
            self.assertIn(expected, actions)

        # 撤销事件中带有撤销时间，访问事件仍指向原包
        revoke_entries = [
            e for e in self.h.repo.list_audit(limit=500)
            if e.action == "grant.revoked"
        ]
        self.assertEqual(len(revoke_entries), 1)
        self.assertEqual(
            revoke_entries[0].detail["receiver_institution_id"], "inst-b"
        )
        self.assertTrue(revoke_entries[0].detail["revoked_at"])
        access_entries = [
            e for e in self.h.repo.list_audit(limit=500)
            if e.action == "grant.accessed"
        ]
        self.assertEqual(access_entries[0].package_id, self.pid)

    def test_receiver_can_revoke(self) -> None:
        grant = self._active_grant(["kind:enterprise_feedback"])
        revoked = self.h.ctx.grants.revoke_grant(
            self.admin_b, grant_id=grant["grant_id"], reason="接收方退出"
        )
        self.assertEqual(revoked["status"], GrantStatus.REVOKED.value)
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.build_package_view(self.admin_b, self.pid)

    def test_repropose_after_revoke_restores_access(self) -> None:
        grant = self._active_grant(["kind:enterprise_feedback"])
        self.h.ctx.grants.revoke_grant(
            self.admin_a, grant_id=grant["grant_id"]
        )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.build_package_view(self.admin_b, self.pid)
        # 重新走双方确认流程后恢复
        self._active_grant(["kind:enterprise_feedback"])
        view = self.h.ctx.packages.build_package_view(self.admin_b, self.pid)
        self.assertFalse(self._find(view, self.sensitive_version)["redacted"])


class GrantHttpTests(unittest.TestCase):
    """经 HTTP 走完整授权流程：中间件即时拦截 + 审计端点留痕可查。"""

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

    def _user(self, user_id, roles, institution_id, token):
        status, body = self.boot.request(
            "POST", "/v1/admin/users",
            {"user_id": user_id, "roles": roles,
             "institution_id": institution_id},
        )
        assert status == 201, body
        status, body = self.boot.request(
            "POST", "/v1/admin/tokens",
            {"user_id": user_id, "token": token},
        )
        assert status == 201, body
        return ApiClient(self.base, token=token)

    def test_grant_flow_over_http(self) -> None:
        admin_a = self._user("admin-a", ["institution_admin"], "inst-a", "tok-a")
        admin_b = self._user("admin-b", ["institution_admin"], "inst-b", "tok-b")
        auditor = self._user("aud", ["auditor"], None, "tok-aud")

        # 授予方准备一份敏感企业反馈并封存
        status, mat = admin_a.request(
            "POST", "/v1/materials",
            {"kind": "enterprise_feedback", "title": "企业反馈",
             "sensitivity": "sensitive"},
        )
        self.assertEqual(status, 201, mat)
        content = "敏感：企业要求匿名".encode("utf-8")
        status, ver = admin_a.request(
            "POST", f"/v1/materials/{mat['material_id']}/versions",
            {"content_base64": base64.b64encode(content).decode("ascii")},
        )
        self.assertEqual(status, 201, ver)
        status, pkg = admin_a.request("POST", "/v1/packages", {"title": "秋审"})
        pid = pkg["package_id"]
        status, _ = admin_a.request(
            "POST", f"/v1/packages/{pid}/entries",
            {"version_id": ver["version_id"]},
        )
        self.assertEqual(status, 201)
        status, _ = admin_a.request("POST", f"/v1/packages/{pid}/seal", {})
        self.assertEqual(status, 200)

        # 无授权：接收方打开视图被拒
        status, body = admin_b.request("GET", f"/v1/packages/{pid}")
        self.assertEqual(status, 403)

        # 授予方发起（proposed 状态尚不放行）
        status, grant = admin_a.request(
            "POST", "/v1/grants",
            {"receiver_institution_id": "inst-b",
             "field_scopes": ["kind:enterprise_feedback"]},
            idempotency_key="grant-1",
        )
        self.assertEqual(status, 201, grant)
        self.assertEqual(grant["status"], "proposed")
        gid = grant["grant_id"]
        status, body = admin_b.request(
            "GET", f"/v1/packages/{pid}/entries/{ver['version_id']}/content",
        )
        self.assertEqual(status, 403)

        # 幂等重放 propose
        status, grant2 = admin_a.request(
            "POST", "/v1/grants",
            {"receiver_institution_id": "inst-b",
             "field_scopes": ["kind:enterprise_feedback"]},
            idempotency_key="grant-1",
        )
        self.assertEqual(status, 201)
        self.assertEqual(grant2["grant_id"], gid)
        self.assertTrue(grant2["replayed"])

        # 接收方确认 -> 生效
        status, active = admin_b.request(
            "POST", f"/v1/grants/{gid}/confirm", {}
        )
        self.assertEqual(status, 200, active)
        self.assertEqual(active["status"], "active")

        # 生效后：视图可见、内容可下载
        status, view = admin_b.request("GET", f"/v1/packages/{pid}")
        self.assertEqual(status, 200, view)
        self.assertFalse(view["entries"][0]["redacted"])
        status, payload, _ = admin_b.request(
            "GET", f"/v1/packages/{pid}/entries/{ver['version_id']}/content",
            raw=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, content)

        # 授予方撤销 -> 新请求立即 403
        status, revoked = admin_a.request(
            "POST", f"/v1/grants/{gid}/revoke",
            {"reason": "合作机构变更授权"},
        )
        self.assertEqual(status, 200, revoked)
        self.assertEqual(revoked["status"], "revoked")
        self.assertIsNotNone(revoked["revoked_at"])
        status, body = admin_b.request("GET", f"/v1/packages/{pid}")
        self.assertEqual(status, 403)
        status, body = admin_b.request(
            "GET", f"/v1/packages/{pid}/entries/{ver['version_id']}/content",
        )
        self.assertEqual(status, 403)

        # 授权记录（含撤销时间）仍可查
        status, stored = auditor.request("GET", f"/v1/grants/{gid}")
        self.assertEqual(status, 200, stored)
        self.assertEqual(stored["status"], "revoked")
        self.assertEqual(stored["revoke_reason"], "合作机构变更授权")

        # 旧审计仍可查看：proposed/confirmed/accessed/revoked 全留痕
        status, audit = auditor.request("GET", "/v1/audit")
        self.assertEqual(status, 200, audit)
        actions = {e["action"] for e in audit["audit"]}
        self.assertTrue(
            {"grant.proposed", "grant.confirmed",
             "grant.accessed", "grant.revoked"} <= actions
        )

        # 非审计角色不能读审计端点
        status, body = admin_b.request("GET", "/v1/audit")
        self.assertEqual(status, 403)


class GrantSchemaMigrationTests(unittest.TestCase):
    """v1 旧库打开时自动升级到 v2：授权表建好且旧数据不受影响。"""

    def test_v1_database_migrates_to_v2(self) -> None:
        import os
        import sqlite3
        import tempfile

        from service_09252_006.persistence.sqlite_repo import (
            _SCHEMA_V1,
            SqliteRepository,
        )

        fd, path = tempfile.mkstemp(prefix="qe-mig-", suffix=".db")
        os.close(fd)
        os.unlink(path)
        try:
            conn = sqlite3.connect(path)
            conn.executescript(_SCHEMA_V1)
            conn.execute(
                "INSERT INTO users(user_id, institution_id, roles_json,"
                " display_name) VALUES('u1','inst-a','[]','')"
            )
            conn.commit()
            conn.close()

            repo = SqliteRepository(path)
            try:
                version = repo._conn.execute(
                    "PRAGMA user_version"
                ).fetchone()[0]
                self.assertEqual(version, 2)
                # 旧数据仍在
                self.assertIsNotNone(repo.get_user("u1"))
                # 授权表可写可读
                from service_09252_006.domain.models import (
                    CrossInstitutionGrant,
                )

                repo.insert_grant(
                    CrossInstitutionGrant(
                        grant_id="grt_x",
                        granter_institution_id="inst-a",
                        receiver_institution_id="inst-b",
                        field_scopes=("kind:enterprise_feedback",),
                        status="proposed",
                        proposed_by="u1",
                        proposed_at="2026-09-27T00:00:00+00:00",
                        confirmed_by=None,
                        confirmed_at=None,
                        revoked_by=None,
                        revoked_at=None,
                        revoke_reason=None,
                    )
                )
                stored = repo.get_grant("grt_x")
                self.assertEqual(
                    stored.field_scopes, ("kind:enterprise_feedback",)
                )
            finally:
                repo.close()
        finally:
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.unlink(path + suffix)
                except FileNotFoundError:
                    pass


if __name__ == "__main__":
    unittest.main()
