"""跨机构授权策略（纯函数，不依赖持久化）。

授权语义：
- 只有双方确认（status=active）且未撤销的授权放行新请求；
- 授权按【字段范围】生效，字段范围取材料类别 MaterialKind
  （syllabus/faculty/assessment/enterprise_feedback）；
- 撤销时刻之后的请求一律拒绝；判定以“当前时刻 > revoked_at”为准，
  因此撤销对新请求立即生效，而历史审计与历史访问记录不受影响；
- 授权只放开“非敏感字段”的跨机构可见性。敏感企业反馈仍受
  disclosure.py 的最小披露约束（有效评审分配/本机构管理员/审计），
  字段授权本身不构成敏感内容的访问依据。
"""
from __future__ import annotations

from datetime import datetime

from .enums import GrantStatus, MaterialKind, Sensitivity
from .models import CrossInstitutionGrant, PackageEntry, ReviewPackage, User

FIELD_SCOPES: frozenset[str] = frozenset(k.value for k in MaterialKind)


def validate_field_scopes(scopes) -> tuple[str, ...]:
    if not scopes:
        raise ValueError("字段范围不能为空")
    normalized = tuple(dict.fromkeys(str(s).strip() for s in scopes if str(s).strip()))
    if not normalized:
        raise ValueError("字段范围不能为空")
    bad = [s for s in normalized if s not in FIELD_SCOPES]
    if bad:
        raise ValueError(f"未知授权字段: {bad}")
    return normalized


def grant_covers(
    grant: CrossInstitutionGrant,
    user: User,
    package: ReviewPackage,
    entry: PackageEntry,
    *,
    now: datetime,
) -> bool:
    """该授权在此刻是否允许 user 跨机构查看包内该条目。"""
    if grant.status != GrantStatus.ACTIVE.value:
        return False
    # 撤销时间是硬边界：撤销后（含边界之后的）任何新请求立即拒绝
    if grant.revoked_at is not None and now_iso_dt(grant.revoked_at) <= now:
        return False
    if package.institution_id != grant.grantor_institution_id:
        return False
    if user.institution_id != grant.recipient_institution_id:
        return False
    if grant.recipient_user_id is not None and grant.recipient_user_id != user.user_id:
        return False
    if entry.kind not in grant.field_scopes:
        return False
    # 敏感企业反馈不随字段授权开放
    if entry.sensitivity == Sensitivity.SENSITIVE.value:
        return False
    return True


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def now_iso_dt(value: str) -> datetime:
    """撤销时间以 UTC ISO 存储，比较时统一到 aware datetime。"""
    dt = parse_iso(value)
    if dt.tzinfo is None:
        from datetime import timezone

        dt = dt.replace(tzinfo=timezone.utc)
    return dt
