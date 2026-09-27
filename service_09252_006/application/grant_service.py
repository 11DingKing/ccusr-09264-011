"""跨机构授权：双方确认的授权生命周期 + 请求访问中间件。

生命周期（双方确认）：
- 授予方机构管理员 propose（记录授予方/接收方/字段范围，状态 proposed）；
- 接收方机构管理员 confirm（状态 active，双方确认完成）；
- 任一方机构管理员 revoke（追加 revoked_at，状态 revoked，记录保留）。

访问中间件（AccessMiddleware）：
- 每个跨机构访问请求都实时查询 SQLite 中的 active 授权，不做缓存；
- 撤销提交后，下一个请求立即被 PermissionDeniedError 拒绝；
- 授权与撤销事件写入审计日志，撤销后历史审计仍可查询。
"""
from __future__ import annotations

from ..domain.enums import GrantStatus, Role
from ..domain.errors import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from ..domain.grants import grant_covers_entry, parse_scopes
from ..domain.models import CrossInstitutionGrant, PackageEntry, ReviewPackage, User
from .base import Service, require_roles

# 允许凭跨机构授权访问数据的角色（接收方机构内）
_GRANT_ACCESS_ROLES = (Role.INSTITUTION_ADMIN, Role.REVIEWER)


class GrantService(Service):
    """跨机构授权的登记、双方确认与撤销。"""

    # ------------------------------------------------------------- 发起
    def propose_grant(
        self,
        actor: User,
        *,
        receiver_institution_id: str,
        field_scopes,
        idempotency_key: str | None = None,
    ) -> dict:
        """授予方机构管理员发起授权；需接收方确认后才生效。"""
        require_roles(actor, Role.INSTITUTION_ADMIN)
        granter = actor.institution_id
        if not granter:
            raise ValidationError("授予方必须属于某个机构")
        if not receiver_institution_id or not isinstance(
            receiver_institution_id, str
        ):
            raise ValidationError("接收方机构不能为空")
        receiver = receiver_institution_id.strip()
        if receiver == granter:
            raise ValidationError("不能向本机构授权（同机构无需跨机构授权）")
        scopes = parse_scopes(field_scopes)

        def work() -> dict:
            grant = CrossInstitutionGrant(
                grant_id=self.ids.new_id("grt"),
                granter_institution_id=granter,
                receiver_institution_id=receiver,
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
                institution_id=granter,
                detail={
                    "grant_id": grant.grant_id,
                    "granter_institution_id": granter,
                    "receiver_institution_id": receiver,
                    "field_scopes": list(scopes),
                },
            )
            return self._grant_dict(grant)

        return self.idempotent(idempotency_key, work)

    # ------------------------------------------------------------- 确认
    def confirm_grant(
        self,
        actor: User,
        *,
        grant_id: str,
        idempotency_key: str | None = None,
    ) -> dict:
        """接收方机构管理员确认授权，双方确认完成后授权生效。"""
        require_roles(actor, Role.INSTITUTION_ADMIN)

        def work() -> dict:
            grant = self._require_grant(grant_id)
            if actor.institution_id != grant.receiver_institution_id:
                raise PermissionDeniedError("只有接收方机构管理员可以确认授权")
            if grant.status == GrantStatus.ACTIVE.value:
                return self._grant_dict(grant, replayed=True)
            if grant.status != GrantStatus.PROPOSED.value:
                raise ConflictError(
                    "授权当前状态不能确认", details={"status": grant.status}
                )
            grant.status = GrantStatus.ACTIVE.value
            grant.confirmed_by = actor.user_id
            grant.confirmed_at = self.clock.now_iso()
            self.repo.update_grant(grant)
            self.audit(
                actor.user_id, "grant.confirmed",
                institution_id=grant.granter_institution_id,
                detail={
                    "grant_id": grant.grant_id,
                    "granter_institution_id": grant.granter_institution_id,
                    "receiver_institution_id": grant.receiver_institution_id,
                    "field_scopes": list(grant.field_scopes),
                },
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
        """任一方机构管理员撤销授权。

        撤销是追加标记（revoked_at），记录与历史审计全部保留；
        撤销提交后访问中间件立即拒绝新请求。
        """
        require_roles(actor, Role.INSTITUTION_ADMIN)

        def work() -> dict:
            grant = self._require_grant(grant_id)
            if actor.institution_id not in (
                grant.granter_institution_id,
                grant.receiver_institution_id,
            ):
                raise PermissionDeniedError("只有授权双方机构可以撤销授权")
            if grant.status == GrantStatus.REVOKED.value:
                return self._grant_dict(grant, replayed=True)
            grant.status = GrantStatus.REVOKED.value
            grant.revoked_by = actor.user_id
            grant.revoked_at = self.clock.now_iso()
            grant.revoke_reason = reason.strip() or None
            self.repo.update_grant(grant)
            self.audit(
                actor.user_id, "grant.revoked",
                institution_id=grant.granter_institution_id,
                detail={
                    "grant_id": grant.grant_id,
                    "granter_institution_id": grant.granter_institution_id,
                    "receiver_institution_id": grant.receiver_institution_id,
                    "field_scopes": list(grant.field_scopes),
                    "revoked_at": grant.revoked_at,
                    "reason": grant.revoke_reason,
                },
            )
            return self._grant_dict(grant)

        return self.idempotent(idempotency_key, work)

    # ------------------------------------------------------------- 查询
    def list_grants(self, actor: User) -> list[dict]:
        """机构管理员看本机构（任一方）的授权；审计/权威机构看全部。"""
        require_roles(
            actor, Role.INSTITUTION_ADMIN, Role.AUDITOR, Role.QUALITY_AUTHORITY
        )
        if actor.has_role(Role.AUDITOR) or actor.has_role(Role.QUALITY_AUTHORITY):
            grants = self.repo.list_grants()
        else:
            as_granter = self.repo.list_grants(
                granter_institution_id=actor.institution_id
            )
            as_receiver = self.repo.list_grants(
                receiver_institution_id=actor.institution_id
            )
            seen: dict[str, CrossInstitutionGrant] = {}
            for g in as_granter + as_receiver:
                seen[g.grant_id] = g
            grants = sorted(seen.values(), key=lambda g: g.proposed_at)
        return [self._grant_dict(g) for g in grants]

    def get_grant(self, actor: User, grant_id: str) -> dict:
        require_roles(
            actor, Role.INSTITUTION_ADMIN, Role.AUDITOR, Role.QUALITY_AUTHORITY
        )
        grant = self._require_grant(grant_id)
        if (
            not actor.has_role(Role.AUDITOR)
            and not actor.has_role(Role.QUALITY_AUTHORITY)
            and actor.institution_id
            not in (grant.granter_institution_id, grant.receiver_institution_id)
        ):
            raise PermissionDeniedError("只能查看本机构相关的授权")
        return self._grant_dict(grant)

    # ------------------------------------------------------------- 内部
    def _require_grant(self, grant_id: str) -> CrossInstitutionGrant:
        grant = self.repo.get_grant(grant_id)
        if grant is None:
            raise NotFoundError("授权不存在", details={"grant_id": grant_id})
        return grant

    @staticmethod
    def _grant_dict(g: CrossInstitutionGrant, *, replayed: bool = False) -> dict:
        return {
            "grant_id": g.grant_id,
            "granter_institution_id": g.granter_institution_id,
            "receiver_institution_id": g.receiver_institution_id,
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


class AccessMiddleware(Service):
    """跨机构访问中间件：每次请求实时核对 SQLite 中的有效授权。

    设计要点：
    - 不缓存授权——撤销提交后，下一个请求立即被拒绝；
    - 全局只读角色（审计/权威机构）与本机构访问不经过授权判定，
      沿用既有的最小披露规则；
    - 通过授权访问的事件写入审计日志，撤销后这些历史审计仍可查询。
    """

    def active_grants_for(
        self, granter_institution_id: str, receiver_institution_id: str
    ) -> list[CrossInstitutionGrant]:
        return self.repo.list_active_grants(
            granter_institution_id, receiver_institution_id
        )

    def entry_visible_via_grant(
        self,
        actor: User,
        *,
        package: ReviewPackage,
        entry: PackageEntry,
    ) -> bool:
        """该用户是否可凭某条有效授权看到此条目（用于逐条目披露判定）。"""
        if actor.institution_id is None:
            return False
        if actor.institution_id == package.institution_id:
            return False  # 本机构走既有披露规则
        if not any(actor.has_role(r) for r in _GRANT_ACCESS_ROLES):
            return False
        grants = self.active_grants_for(
            package.institution_id, actor.institution_id
        )
        return any(
            grant_covers_entry(
                g,
                granter_institution_id=package.institution_id,
                receiver_institution_id=actor.institution_id,
                entry=entry,
            )
            for g in grants
        )

    def enforce_package_access(self, actor: User, package: ReviewPackage) -> None:
        """打开他机构评审包视图前的拦截：无任何有效授权覆盖包内条目即拒绝。"""
        if actor.institution_id is None:
            raise PermissionDeniedError("跨机构访问需要机构身份")
        if not any(actor.has_role(r) for r in _GRANT_ACCESS_ROLES):
            raise PermissionDeniedError("当前角色不能凭跨机构授权访问")
        grants = self.active_grants_for(
            package.institution_id, actor.institution_id
        )
        covered = any(
            grant_covers_entry(
                g,
                granter_institution_id=package.institution_id,
                receiver_institution_id=actor.institution_id,
                entry=entry,
            )
            for g in grants
            for entry in package.entries
        )
        if not covered:
            raise PermissionDeniedError(
                "无有效跨机构授权覆盖该评审包字段范围",
                details={
                    "granter_institution_id": package.institution_id,
                    "receiver_institution_id": actor.institution_id,
                },
            )

    def enforce_entry_access(
        self, actor: User, *, package: ReviewPackage, entry: PackageEntry
    ) -> None:
        """下载他机构条目内容前的拦截：无覆盖该条目的有效授权即拒绝。"""
        if actor.institution_id is None:
            raise PermissionDeniedError("跨机构访问需要机构身份")
        if not any(actor.has_role(r) for r in _GRANT_ACCESS_ROLES):
            raise PermissionDeniedError("当前角色不能凭跨机构授权访问")
        if not self.entry_visible_via_grant(actor, package=package, entry=entry):
            raise PermissionDeniedError(
                "无有效跨机构授权覆盖该材料字段范围",
                details={
                    "granter_institution_id": package.institution_id,
                    "receiver_institution_id": actor.institution_id,
                    "material_id": entry.material_id,
                    "kind": entry.kind,
                },
            )

    def audit_grant_access(
        self,
        actor: User,
        *,
        package: ReviewPackage,
        entry: PackageEntry | None = None,
    ) -> None:
        """记录一次凭授权的跨机构访问（撤销后仍可被审计查询）。"""
        detail = {
            "granter_institution_id": package.institution_id,
            "receiver_institution_id": actor.institution_id,
        }
        if entry is not None:
            detail.update(
                {
                    "entry_id": entry.entry_id,
                    "material_id": entry.material_id,
                    "version_id": entry.version_id,
                    "kind": entry.kind,
                }
            )
        self.audit(
            actor.user_id, "grant.accessed",
            package_id=package.package_id,
            institution_id=package.institution_id,
            detail=detail,
        )
