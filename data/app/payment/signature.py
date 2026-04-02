"""基于 HMAC-SHA256 的参数签名验证器。

翻译自 Pay with 302 官方 TypeScript demo，保持签名算法完全一致。
"""

import hmac
import hashlib
import json
import time
import urllib.parse
from typing import Any, Optional


# 默认排除的签名字段
_DEFAULT_EXCLUDE_KEYS = frozenset({"sign", "signature"})


class SignatureValidator:
    """HMAC-SHA256 参数签名验证器。"""

    def __init__(self, secret: str):
        if not secret or not secret.strip():
            raise ValueError("Secret 不能为空")
        self.secret = secret

    def generate_signature(
        self,
        params: dict[str, Any],
        timestamp: Optional[int] = None,
        exclude_keys: Optional[set[str]] = None,
    ) -> str:
        """生成签名。"""
        excl = exclude_keys if exclude_keys is not None else _DEFAULT_EXCLUDE_KEYS

        filtered: dict[str, Any] = {}
        for key, value in params.items():
            if key not in excl and _is_valid_value(value):
                filtered[key] = value

        if timestamp is not None:
            filtered["timestamp"] = timestamp

        sign_string = _build_sign_string(filtered)
        return hmac.new(
            self.secret.encode("utf-8"),
            sign_string.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def validate(
        self,
        params: dict[str, Any],
        signature: str,
        timestamp_tolerance: Optional[int] = None,
    ) -> bool:
        """验证签名是否合法。使用常量时间比较防止时序攻击。"""
        if timestamp_tolerance is not None and "timestamp" in params:
            if not _check_timestamp(params["timestamp"], timestamp_tolerance):
                return False

        expected = self.generate_signature(params)
        return hmac.compare_digest(expected, signature)


# --------------- 内部工具函数 ---------------


def _is_valid_value(value: Any) -> bool:
    """判断值是否有效（非空）。"""
    if value is None:
        return False
    if isinstance(value, str) and value == "":
        return False
    if isinstance(value, dict) and len(value) == 0:
        return False
    if isinstance(value, list) and len(value) == 0:
        return False
    return True


def _sort_object_keys(obj: Any) -> Any:
    """递归排序对象键，确保与 TypeScript JSON.stringify 一致。"""
    if isinstance(obj, dict):
        return {k: _sort_object_keys(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_sort_object_keys(item) for item in obj]
    return obj


def _normalize_value(value: Any) -> str:
    """统一值的字符串表示。"""
    if isinstance(value, dict) or isinstance(value, list):
        return json.dumps(_sort_object_keys(value), separators=(",", ":"), ensure_ascii=False)
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def _build_sign_string(params: dict[str, Any]) -> str:
    """构建待签名字符串：按 key 字典序排序，URL 编码，& 连接。"""
    sorted_keys = sorted(params.keys())
    parts = []
    for key in sorted_keys:
        encoded_key = urllib.parse.quote(str(key), safe="")
        encoded_value = urllib.parse.quote(_normalize_value(params[key]), safe="")
        parts.append(f"{encoded_key}={encoded_value}")
    return "&".join(parts)


def _check_timestamp(timestamp: Any, tolerance: int) -> bool:
    """检查时间戳是否在容差范围内。"""
    try:
        ts = int(timestamp)
    except (ValueError, TypeError):
        return False
    current = int(time.time())
    return abs(current - ts) <= tolerance


# --------------- 便捷函数 ---------------


def quick_sign(params: dict[str, Any], secret: str) -> str:
    """快速生成签名。"""
    return SignatureValidator(secret).generate_signature(params)


def quick_validate(params: dict[str, Any], signature: str, secret: str) -> bool:
    """快速验证签名。"""
    return SignatureValidator(secret).validate(params, signature)
