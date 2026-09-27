"""跨机构授权：双方确认、字段范围、撤销即时生效、旧审计保留。

覆盖：
- 授予方提议 + 接收方确认（双方确认）后授权才生效；
- 授权分别记录授予方、接收方与字段范围，并落 SQLite；
- 撤销后新请求立即被拒绝（中间件实时查库），撤销时间已记录；
- 撤销不删除历史：旧审计（提议/确认/撤销/拒绝）仍可查看；
- 字段范围外的条目与敏感企业反馈不随授权开放。
"""
import sqlite3
import unittest

from service_09252_006.domain.enums import GrantStatus, MaterialKind, Role, Sensitivity
from service_09252_006.domain.errors import (
    ConflictError,
    PermissionDeniedError,
    ValidationError,
)
from tests.flow import seal_new_package, upload_material
from tests.support import Harness


class CrossInstitutionGrantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin_a = self.h.user("admin-a", Role.INSTITUTION_ADMIN)  # inst-a
        self.admin_b = self.h.user(
            "admin-b", Role.INSTITUTION_ADMIN, institution_id="inst-b"
        )
        self.member_b = self.h.user(
            "mem-b", Role.INSTITUTION_SUBMITTER, institution_id="inst-b"
        )
        self.admin_c = self.h.user(
            "admin-c", Role.INSTITUTION_ADMIN, institution_id="inst-c"
        )
        self.auditor = self.h.user("aud", Role.AUDITOR, institution_id=None)
        # inst-a 的已封存包：大纲(normal) + 企业反馈(sensitive)
        self.sealed = seal_new_package(self.h, self.admin_a)
        self.pid = self.sealed.package_id
        self.normal_version = self.sealed.items[0].version["version_id"]
        self.sensitive_version = self.sealed.items[1].version["version_id"]

    def tearDown(self) -> None:
        self.h.close()

    # ------------------------------------------------------------ 辅助
    def _propose(self, scopes=("syllabus",), recipient_user_id=None) -> dict:
        return self.h.ctx.grants.propose_grant(
            self.admin_a,
            recipient_institution_id="inst-b",
            field_scopes=list(scopes),
            recipient_user_id=recipient_user_id,
        )

    def _active_grant(self, scopes=("syllabus",), recipient_user_id=None) -> dict:
        grant = self._propose(scopes, recipient_user_id)
        return self.h.ctx.grants.confirm_grant(
            self.admin_b, grant_id=grant["grant_id"]
        )

    def _find(self, view, version_id):
        return next(e for e in view["entries"] if e["version_id"] == version_id)

    # ---------------------------------------------------- 双方确认流程
    def test_proposed_grant_does_not_allow_access_until_confirmed(self) -> None:
        grant = self._propose()
        self.assertEqual(grant["status"], GrantStatus.PROPOSED.value)
        # 仅提议、未确认：新请求仍被拒绝
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.build_package_view(self.member_b, self.pid)

        confirmed = self.h.ctx.grants.confirm_grant(
            self.admin_b, grant_id=grant["grant_id"]
        )
        self.assertEqual(confirmed["status"], GrantStatus.ACTIVE.value)
        self.assertEqual(confirmed["confirmed_by"], "admin-b")
        self.assertIsNotNone(confirmed["confirmed_at"])

        view = self.h.ctx.packages.build_package_view(self.member_b, self.pid)
        self.assertEqual(view["via_grant"]["grant_id"], grant["grant_id"])

    def test_grant_records_parties_and_field_scopes(self) -> None:
        grant = self._active_grant(scopes=["syllabus", "assessment"])
        self.assertEqual(grant["grantor_institution_id"], "inst-a")
        self.assertEqual(grant["recipient_institution_id"], "inst-b")
        self.assertEqual(grant["field_scopes"], ["syllabus", "assessment"])
        self.assertEqual(grant["proposed_by"], "admin-a")

        # 落库到 SQLite：授予方/接收方/字段范围可直接查出
        conn = sqlite3.connect(self.h.db_path)
        try:
            row = conn.execute(
                "SELECT grantor_institution_id, recipient_institution_id,"
                " field_scopes_json, status, revoked_at FROM grants"
                " WHERE grant_id = ?",
                (grant["grant_id"],),
            ).fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "inst-a")
        self.assertEqual(row[1], "inst-b")
        self.assertIn("assessment", row[2])
        self.assertEqual(row[3], "active")
        self.assertIsNone(row[4])

    def test_only_recipient_can_confirm(self) -> None:
        grant = self._propose()
        # 授予方不能替接收方确认
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.grants.confirm_grant(self.admin_a, grant_id=grant["grant_id"])
        # 无关第三方不能确认
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.grants.confirm_grant(self.admin_c, grant_id=grant["grant_id"])

    def test_confirm_requires_valid_state(self) -> None:
        grant = self._active_grant()
        self.h.ctx.grants.revoke_grant(self.admin_a, grant_id=grant["grant_id"])
        with self.assertRaises(ConflictError):
            self.h.ctx.grants.confirm_grant(self.admin_b, grant_id=grant["grant_id"])

    def test_invalid_field_scopes_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            self._propose(scopes=[])
        with self.assertRaises(ValidationError):
            self._propose(scopes=["salary_records"])

    # ---------------------------------------------------- 字段范围放行
    def test_active_grant_allows_scoped_fields_only(self) -> None:
        self._active_grant(scopes=["syllabus"])
        view = self.h.ctx.packages.build_package_view(self.member_b, self.pid)
        # 大纲在授权范围内：可见
        self.assertFalse(self._find(view, self.normal_version)["redacted"])
        # 敏感企业反馈：即使字段范围写了也不开放（且本授权未含该字段）
        self.assertTrue(self._find(view, self.sensitive_version)["redacted"])

        meta, data, _ = self.h.ctx.packages.download_entry(
            self.member_b, package_id=self.pid, version_id=self.normal_version
        )
        self.assertEqual(data, "大纲 v1".encode("utf-8"))

    def test_sensitive_feedback_never_exposed_via_grant(self) -> None:
        # 即使字段范围显式包含 enterprise_feedback，敏感条目也不开放
        self._active_grant(scopes=["enterprise_feedback", "syllabus"])
        view = self.h.ctx.packages.build_package_view(self.member_b, self.pid)
        self.assertTrue(self._find(view, self.sensitive_version)["redacted"])
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.download_entry(
                self.member_b,
                package_id=self.pid,
                version_id=self.sensitive_version,
            )

    def test_grant_scoped_to_specific_recipient_user(self) -> None:
        self._active_grant(scopes=["syllabus"], recipient_user_id="mem-b")
        # 指定接收人可用
        view = self.h.ctx.packages.build_package_view(self.member_b, self.pid)
        self.assertFalse(self._find(view, self.normal_version)["redacted"])
        # 同机构其他用户不在授权内
        other_b = self.h.user(
            "mem-b2", Role.INSTITUTION_SUBMITTER, institution_id="inst-b"
        )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.build_package_view(other_b, self.pid)

    def test_multiple_grants_union_scopes_and_partial_revoke(self) -> None:
        """机构级 + 用户级授权并存，字段范围取并集；撤销其中一条立即收缩。"""
        syl = upload_material(
            self.h, self.admin_a,
            kind=MaterialKind.SYLLABUS.value,
            data="大纲".encode("utf-8"), title="大纲",
            sensitivity=Sensitivity.NORMAL.value,
        )
        assess = upload_material(
            self.h, self.admin_a,
            kind=MaterialKind.ASSESSMENT.value,
            data="考核".encode("utf-8"), title="考核",
            sensitivity=Sensitivity.NORMAL.value,
        )
        feedback = upload_material(
            self.h, self.admin_a,
            kind=MaterialKind.ENTERPRISE_FEEDBACK.value,
            data="敏感反馈".encode("utf-8"), title="反馈",
            sensitivity=Sensitivity.SENSITIVE.value,
        )
        sealed = seal_new_package(
            self.h, self.admin_a, items=[syl, assess, feedback], title="多字段包"
        )
        v_syl, v_assess, v_fb = (
            sealed.items[0].version["version_id"],
            sealed.items[1].version["version_id"],
            sealed.items[2].version["version_id"],
        )

        # 机构级授权：syllabus
        inst_grant = self._active_grant(scopes=["syllabus"])
        # 用户级授权：assessment（仅 mem-b）
        user_grant = self._active_grant(
            scopes=["assessment"], recipient_user_id="mem-b"
        )

        other_b = self.h.user(
            "mem-b2", Role.INSTITUTION_SUBMITTER, institution_id="inst-b"
        )
        view = self.h.ctx.packages.build_package_view(self.member_b, sealed.package_id)
        self.assertFalse(self._find(view, v_syl)["redacted"])
        self.assertFalse(self._find(view, v_assess)["redacted"])  # 并集
        self.assertTrue(self._find(view, v_fb)["redacted"])
        # mem-b2 只有机构级授权，看不到 assessment
        view2 = self.h.ctx.packages.build_package_view(other_b, sealed.package_id)
        self.assertFalse(self._find(view2, v_syl)["redacted"])
        self.assertTrue(self._find(view2, v_assess)["redacted"])

        # 撤销用户级 assessment 授权：新请求立即收缩，syllabus 仍可访问
        self.h.ctx.grants.revoke_grant(self.admin_a, grant_id=user_grant["grant_id"])
        view3 = self.h.ctx.packages.build_package_view(self.member_b, sealed.package_id)
        self.assertFalse(self._find(view3, v_syl)["redacted"])
        self.assertTrue(self._find(view3, v_assess)["redacted"])
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.download_entry(
                self.member_b, package_id=sealed.package_id, version_id=v_assess
            )

        # 再撤销机构级授权：新请求整体立即拒绝
        self.h.ctx.grants.revoke_grant(self.admin_a, grant_id=inst_grant["grant_id"])
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.build_package_view(self.member_b, sealed.package_id)

    # ---------------------------------------------------- 撤销即时生效
    def test_revoke_immediately_rejects_new_requests(self) -> None:
        grant = self._active_grant(scopes=["syllabus"])
        # 撤销前可访问
        view = self.h.ctx.packages.build_package_view(self.member_b, self.pid)
        self.assertFalse(self._find(view, self.normal_version)["redacted"])

        revoked = self.h.ctx.grants.revoke_grant(
            self.admin_a, grant_id=grant["grant_id"], reason="合作终止"
        )
        self.assertEqual(revoked["status"], GrantStatus.REVOKED.value)
        self.assertEqual(revoked["revoked_by"], "admin-a")
        self.assertIsNotNone(revoked["revoked_at"])
        self.assertEqual(revoked["revoke_reason"], "合作终止")

        # 新请求立即被拒绝（视图与下载都走中间件实时查库）
        with self.assertRaises(PermissionDeniedError) as ctx:
            self.h.ctx.packages.build_package_view(self.member_b, self.pid)
        self.assertIn("撤销", ctx.exception.message)
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.download_entry(
                self.member_b, package_id=self.pid, version_id=self.normal_version
            )

        # 撤销时间已落 SQLite
        conn = sqlite3.connect(self.h.db_path)
        try:
            row = conn.execute(
                "SELECT status, revoked_at, revoked_by FROM grants WHERE grant_id = ?",
                (grant["grant_id"],),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row[0], "revoked")
        self.assertIsNotNone(row[1])
        self.assertEqual(row[2], "admin-a")

    def test_revoke_is_idempotent_and_recipient_can_revoke(self) -> None:
        grant = self._active_grant()
        first = self.h.ctx.grants.revoke_grant(self.admin_b, grant_id=grant["grant_id"])
        second = self.h.ctx.grants.revoke_grant(
            self.admin_a, grant_id=grant["grant_id"]
        )
        self.assertEqual(first["revoked_at"], second["revoked_at"])
        self.assertTrue(second["replayed"])

    def test_third_party_cannot_revoke(self) -> None:
        grant = self._active_grant()
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.grants.revoke_grant(self.admin_c, grant_id=grant["grant_id"])

    # ---------------------------------------------------- 旧审计仍可查看
    def test_audit_trail_survives_revocation(self) -> None:
        grant = self._active_grant(scopes=["syllabus"])
        gid = grant["grant_id"]
        # 产生一次成功访问 + 撤销 + 一次被拒绝的访问
        self.h.ctx.packages.build_package_view(self.member_b, self.pid)
        self.h.ctx.grants.revoke_grant(self.admin_a, grant_id=gid, reason="到期")
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.build_package_view(self.member_b, self.pid)

        # 撤销后旧审计仍可查看：提议/确认/撤销/拒绝 全在
        audit = self.h.ctx.grants.grant_audit(self.auditor, gid)
        actions = [a["action"] for a in audit]
        self.assertIn("grant.proposed", actions)
        self.assertIn("grant.confirmed", actions)
        self.assertIn("grant.revoked", actions)
        self.assertIn("grant.access_denied", actions)

        # 授权记录本身也未删除，撤销时间可查
        detail = self.h.ctx.grants.get_grant(self.auditor, gid)
        self.assertEqual(detail["status"], "revoked")
        self.assertIsNotNone(detail["revoked_at"])

        # 授权双方机构也能查看审计
        audit_b = self.h.ctx.grants.grant_audit(self.admin_b, gid)
        self.assertEqual(len(audit_b), len(audit))
        # 无关第三方不可见
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.grants.grant_audit(self.admin_c, gid)

    def test_list_grants_scoped_by_party(self) -> None:
        self._active_grant()
        mine_a = self.h.ctx.grants.list_grants(self.admin_a)
        mine_b = self.h.ctx.grants.list_grants(self.admin_b)
        self.assertEqual(len(mine_a), 1)
        self.assertEqual(len(mine_b), 1)
        # 第三方机构看不到
        self.assertEqual(self.h.ctx.grants.list_grants(self.admin_c), [])
        # 审计可见全部
        self.assertEqual(len(self.h.ctx.grants.list_grants(self.auditor)), 1)


if __name__ == "__main__":
    unittest.main()
