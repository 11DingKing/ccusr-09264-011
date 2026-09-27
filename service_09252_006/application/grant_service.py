"""跨机构授权服务：提议、双方确认、撤销，以及访问路径上的实时中间件。

业务规则：
- 授权记录分别保存【授予方机构、接收方机构/用户、字段范围】；
- 授予方机构管理员提议后，必须由接收方机构管理员确认（双方确认），
  授权才进入 active 并放行新请求；
- 任一方机构管理员（或质量权威机构）可撤销；撤销是追加标记
  （revoked_by/revoked_at/revoke_reason），记录永不删除；
- require_access 是跨机构访问的中间件：每个新请求实时查询 SQLite，
  撤销落库后下一个请求立即被拒绝；授权与撤销的审计历史始终可查。
"""
from __future__ import annotations

from ..domain.enums import GrantStatus, Role
from ..domain.errors import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from ..domain.grants import validate_field_scopes
from ..domain.models import CrossInstitutionGrant, ReviewPackage, User
from .base import Service, require_roles


class GrantService(Service):
    # --------------------------------------------------------- 提议（授予方）
    def propose_grant(
        self,
        actor: User,
        *,
        recipient_institution_id: str,
        field_scopes,
        recipient_user_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        require_roles(actor, Role.INSTITUTION_ADMIN, Role.QUALITY_AUTHORITY)
        if not actor.institution_id:
            raise PermissionDeniedError("授予方必须属于某个机构")
        recipient = (recipient_institution_id or "").strip()
        if not recipient:
            raise ValidationError("接收方机构不能为空")
        if recipient == actor.institution_id:
            raise ValidationError("不能对本机构发起跨机构授权")
        try:
            scopes = validate_field_scopes(field_scopes)
        except ValueError as exc:
            raise ValidationError(str(exc))

        def work() -> dict:
            if recipient_user_id is not None:
                target = self.repo.get_user(recipient_user_id)
                if target is None:
                    raise ValidationError(
                        "指定的接收人不存在",
                        details={"recipient_user_id": recipient_user_id},
                    )
                if target.institution_id != recipient:
                    raise ValidationError(
                        "接收人不属于接收方机构",
                        details={
                            "recipient_user_id": recipient_user_id,
                            "user_institution_id": target.institution_id,
                        },
                    )
            grant = CrossInstitutionGrant(
                grant_id=self.ids.new_id("grt"),
                grantor_institution_id=actor.institution_id or "",
                recipient_institution_id=recipient,
                recipient_user_id=recipient_user_id,
                field_scopes=scopes,
                status=GrantStatus.PROPOSED.value,
                proposed_by=actor.user_id,
                proposed_at=self.clock.now_iso(),
                confirmed_by=None,
                confirmed_at=None,
                revoked_by=None,
                revoked_at=None,
                revoke_reason=None,
            )
            self.repo.insert_grant(grant)
            self.audit(
                actor.user_id, "grant.proposed",
                institution_id=grant.grantor_institution_id,
                detail={
                    "grant_id": grant.grant_id,
                    "recipient_institution_id": recipient,
                    "recipient_user_id": recipient_user_id,
                    "field_scopes": list(scopes),
                },
            )
            return self._grant_dict(grant)

        return self.idempotent(idempotency_key, work)

    # --------------------------------------------------------- 确认（接收方）
    def confirm_grant(
        self,
        actor: User,
        *,
        grant_id: str,
        idempotency_key: str | None = None,
    ) -> dict:
        """双方确认的第二方：仅接收方机构管理员确认后授权生效。

        质量权威机构不是数据共享的当事方，不能代替任何一方确认。
        """
        require_roles(actor, Role.INSTITUTION_ADMIN)

        def work() -> dict:
            grant = self._require_grant(grant_id)
            if actor.institution_id != grant.recipient_institution_id:
                raise PermissionDeniedError("只能由接收方机构确认该授权")
            if grant.status == GrantStatus.ACTIVE.value:
                return self._grant_dict(grant, replayed=True)
            if grant.status != GrantStatus.PROPOSED.value:
                raise ConflictError(
                    "授权当前状态不能确认",
                    details={"status": grant.status},
                )
            grant.status = GrantStatus.ACTIVE.value
            grant.confirmed_by = actor.user_id
            grant.confirmed_at = self.clock.now_iso()
            self.repo.update_grant(grant)
            self.audit(
                actor.user_id, "grant.confirmed",
                institution_id=grant.recipient_institution_id,
                detail={"grant_id": grant_id},
            )
            return self._grant_dict(grant)

        return self.idempotent(idempotency_key, work)

    # ------------------------------------------------------------- 撤销
    def revoke_grant(
        self,
        actor: User,
        *,
        grant_id: str,
        reason: str = "",
        idempotency_key: str | None = None,
    ) -> dict:
        """任一方撤销：记录撤销时间，新请求立即拒绝，历史记录保留。"""
        require_roles(actor, Role.INSTITUTION_ADMIN, Role.QUALITY_AUTHORITY)

        def work() -> dict:
            grant = self._require_grant(grant_id)
            if not actor.has_role(Role.QUALITY_AUTHORITY) and actor.institution_id not in (
                grant.grantor_institution_id,
                grant.recipient_institution_id,
            ):
                raise PermissionDeniedError("只有授权双方机构可以撤销该授权")
            if grant.status == GrantStatus.REVOKED.value:
                return self._grant_dict(grant, replayed=True)
            grant.status = GrantStatus.REVOKED.value
            grant.revoked_by = actor.user_id
            grant.revoked_at = self.clock.now_iso()
            grant.revoke_reason = reason.strip() or None
            self.repo.update_grant(grant)
            self.audit(
                actor.user_id, "grant.revoked",
                institution_id=actor.institution_id,
                detail={
                    "grant_id": grant_id,
                    "revoked_at": grant.revoked_at,
                    "reason": grant.revoke_reason,
                },
            )
            return self._grant_dict(grant)

        return self.idempotent(idempotency_key, work)

    # ------------------------------------------------- 中间件：新请求闸门
    def require_access(
        self, actor: User, package: ReviewPackage
    ) -> list[CrossInstitutionGrant]:
        """跨机构访问中间件：每个新请求实时校验，撤销后立即拒绝。

        返回当前生效的授权列表（机构级与用户级可并存，字段范围取并集）；
        无生效授权时抛出 PermissionDeniedError——若该机构对曾被授权但
        已撤销，错误信息明确指向“授权已撤销”，并记录拒绝审计。
        """
        grants = self.repo.find_active_grants(
            package.institution_id,
            actor.institution_id or "",
            actor.user_id,
        )
        if grants:
            return grants
        prior = self.repo.list_grants(
            grantor_institution_id=package.institution_id,
            recipient_institution_id=actor.institution_id,
        )
        revoked = [g for g in prior if g.status == GrantStatus.REVOKED.value]
        if revoked:
            latest = revoked[-1]
            self.audit(
                actor.user_id, "grant.access_denied",
                package_id=package.package_id,
                institution_id=package.institution_id,
                detail={
                    "grant_id": latest.grant_id,
                    "reason": "grant_revoked",
                    "revoked_at": latest.revoked_at,
                },
            )
            raise PermissionDeniedError(
                "跨机构授权已撤销，新的访问请求被拒绝",
                details={
                    "grant_id": latest.grant_id,
                    "revoked_at": latest.revoked_at,
                },
            )
        raise PermissionDeniedError("不能查看其他机构评审包")

    # ------------------------------------------------------------- 查询
    def get_grant(self, actor: User, grant_id: str) -> dict:
        """授权详情（含字段范围与撤销时间）。撤销后依然可查。"""
        grant = self._require_grant(grant_id)
        self._require_party_or_oversight(actor, grant)
        return self._grant_dict(grant)

    def list_grants(self, actor: User) -> list[dict]:
        if actor.has_role(Role.AUDITOR) or actor.has_role(Role.QUALITY_AUTHORITY):
            grants = self.repo.list_grants()
        elif actor.institution_id:
            granted = self.repo.list_grants(
                grantor_institution_id=actor.institution_id
            )
            received = self.repo.list_grants(
                recipient_institution_id=actor.institution_id
            )
            by_id = {g.grant_id: g for g in granted + received}
            grants = sorted(by_id.values(), key=lambda g: g.proposed_at)
        else:
            raise PermissionDeniedError("当前身份没有机构归属，无法列出授权")
        return [self._grant_dict(g) for g in grants]

    def grant_audit(self, actor: User, grant_id: str, *, limit: int = 200) -> list[dict]:
        """该授权相关的审计轨迹。

        撤销只追加标记、不删除任何审计，因此撤销后旧审计仍可查看。
        """
        grant = self._require_grant(grant_id)
        self._require_party_or_oversight(actor, grant)
        entries = self.repo.list_audit_by_grant(grant_id)
        return [
            {
                "audit_id": e.audit_id,
                "package_id": e.package_id,
                "institution_id": e.institution_id,
                "actor_id": e.actor_id,
                "action": e.action,
                "at": e.at,
                "detail": e.detail,
            }
            for e in entries[:limit]
        ]

    # ------------------------------------------------------------- 内部
    def _require_grant(self, grant_id: str) -> CrossInstitutionGrant:
        grant = self.repo.get_grant(grant_id)
        if grant is None:
            raise NotFoundError("跨机构授权不存在", details={"grant_id": grant_id})
        return grant

    @staticmethod
    def _require_party_or_oversight(actor: User, grant: CrossInstitutionGrant) -> None:
        if actor.has_role(Role.AUDITOR) or actor.has_role(Role.QUALITY_AUTHORITY):
            return
        if actor.institution_id in (
            grant.grantor_institution_id,
            grant.recipient_institution_id,
        ):
            return
        raise PermissionDeniedError("只有授权双方或监管角色可以查看该授权")

    @staticmethod
    def _grant_dict(g: CrossInstitutionGrant, *, replayed: bool = False) -> dict:
        return {
            "grant_id": g.grant_id,
            "grantor_institution_id": g.grantor_institution_id,
            "recipient_institution_id": g.recipient_institution_id,
            "recipient_user_id": g.recipient_user_id,
            "field_scopes": list(g.field_scopes),
            "status": g.status,
            "proposed_by": g.proposed_by,
            "proposed_at": g.proposed_at,
            "confirmed_by": g.confirmed_by,
            "confirmed_at": g.confirmed_at,
            "revoked_by": g.revoked_by,
            "revoked_at": g.revoked_at,
            "revoke_reason": g.revoke_reason,
            "replayed": replayed,
        }
