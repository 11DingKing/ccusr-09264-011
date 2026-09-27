"""跨机构授权策略（纯函数，不依赖数据库与 HTTP）。

授权记录见 domain.models.CrossInstitutionGrant：授予方机构把若干【字段范围】
让渡给接收方机构，经接收方确认后生效；任一方撤销后记录保留但不再放行。

字段范围（field scope）取值：
- ``kind:<material_kind>``   某一类材料（如 kind:enterprise_feedback）；
- ``material:<material_id>`` 某一份具体材料。

访问判定只看“当前状态为 active 的授权”——撤销只追加 revoked_at，
策略层不保留任何缓存，因此撤销一旦提交，下一次请求即按无授权处理。
"""
from __future__ import annotations

import re

from .enums import GrantStatus
from .enums import MaterialKind
from .errors import ValidationError
from .models import CrossInstitutionGrant, PackageEntry

_MATERIAL_SCOPE_RE = re.compile(r"^material:[A-Za-z0-9_\-]{1,64}$")
_KIND_PREFIX = "kind:"
_MATERIAL_PREFIX = "material:"


def parse_scopes(raw_scopes) -> tuple[str, ...]:
    """校验并归一化字段范围；重复项去重，保持输入顺序。"""
    if not raw_scopes or not isinstance(raw_scopes, (list, tuple)):
        raise ValidationError(
            "字段范围不能为空", details={"field_scopes": raw_scopes}
        )
    valid_kinds = {k.value for k in MaterialKind}
    seen: list[str] = []
    for item in raw_scopes:
        if not isinstance(item, str) or not item.strip():
            raise ValidationError("字段范围必须是非空字符串", details={"bad": item})
        scope = item.strip()
        if scope.startswith(_KIND_PREFIX):
            kind = scope[len(_KIND_PREFIX):]
            if kind not in valid_kinds:
                raise ValidationError(
                    "未知材料类型范围", details={"kind": kind}
                )
        elif scope.startswith(_MATERIAL_PREFIX):
            if not _MATERIAL_SCOPE_RE.fullmatch(scope):
                raise ValidationError(
                    "材料范围格式非法（material:<material_id>）",
                    details={"scope": scope},
                )
        else:
            raise ValidationError(
                "字段范围必须以 kind: 或 material: 开头",
                details={"scope": scope},
            )
        if scope not in seen:
            seen.append(scope)
    return tuple(seen)


def scope_covers(scope: str, entry: PackageEntry) -> bool:
    if scope.startswith(_KIND_PREFIX):
        return scope == _KIND_PREFIX + entry.kind
    if scope.startswith(_MATERIAL_PREFIX):
        return scope == _MATERIAL_PREFIX + entry.material_id
    return False


def grant_is_active(grant: CrossInstitutionGrant) -> bool:
    return grant.status == GrantStatus.ACTIVE.value and grant.revoked_at is None


def grant_covers_entry(
    grant: CrossInstitutionGrant,
    *,
    granter_institution_id: str,
    receiver_institution_id: str,
    entry: PackageEntry,
) -> bool:
    """该授权在当前时刻是否覆盖指定条目（机构方向 + 字段范围 + 未撤销）。"""
    if not grant_is_active(grant):
        return False
    if grant.granter_institution_id != granter_institution_id:
        return False
    if grant.receiver_institution_id != receiver_institution_id:
        return False
    return any(scope_covers(s, entry) for s in grant.field_scopes)


def grants_cover_entry(
    grants: list[CrossInstitutionGrant],
    *,
    granter_institution_id: str,
    receiver_institution_id: str,
    entry: PackageEntry,
) -> bool:
    return any(
        grant_covers_entry(
            g,
            granter_institution_id=granter_institution_id,
            receiver_institution_id=receiver_institution_id,
            entry=entry,
        )
        for g in grants
    )
