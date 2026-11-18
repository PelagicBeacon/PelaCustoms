"""通行证（clearance cookie）的签发与校验。

无状态：cookie 自身就是 HMAC 签名过的 JSON，判定时不查任何共享存储。
站点之间用「主密钥 + sitekey」派生子密钥，一个站点被泄露不会波及其他站点。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

#: 通行证格式标记，方便以后换算法而不误读旧票
KIND = "clear"


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode((text + "=" * (-len(text) % 4)).encode())


def derive_key(master: str, sitekey: str) -> str:
    """主密钥 + sitekey 派生出该站点的签名密钥。"""
    return hmac.new(master.encode(), ("pelacustoms:" + sitekey).encode(),
                    hashlib.sha256).hexdigest()


def pack(key: str, payload: dict) -> str:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(key.encode(), body, hashlib.sha256).hexdigest()
    return _b64e(body) + "." + sig


def unpack(key: str, token: str) -> dict | None:
    if not token or not isinstance(token, str) or token.count(".") != 1:
        return None
    body_b64, sig = token.split(".", 1)
    try:
        body = _b64d(body_b64)
    except Exception:
        return None
    expected = hmac.new(key.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return None
    try:
        payload = json.loads(body.decode())
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


# ============================================================
# 指纹
# ============================================================
def ip_fingerprint(ip: str | None) -> str:
    return hashlib.sha256((ip or "").encode()).hexdigest()[:16]


def ua_fingerprint(ua: str | None) -> str:
    return hashlib.sha256((ua or "").encode()).hexdigest()[:16]


# ============================================================
# 签发 / 校验
# ============================================================
def issue(key: str, sitekey: str, level: int, ttl: float,
          ip: str | None, ua: str | None,
          bind_ip: bool, bind_ua: bool) -> tuple[str, int]:
    """返回 (cookie 值, 过期时间戳)。"""
    now = int(time.time())
    exp = now + max(1, int(ttl))
    payload = {
        "k": KIND,
        "sk": sitekey,
        "lvl": int(level),
        "iat": now,
        "exp": exp,
        "jti": secrets.token_hex(8),
    }
    if bind_ip:
        payload["ip"] = ip_fingerprint(ip)
    if bind_ua:
        payload["ua"] = ua_fingerprint(ua)
    return pack(key, payload), exp


def verify(key: str, token: str, sitekey: str, ip: str | None, ua: str | None,
           bind_ip: bool, bind_ua: bool) -> tuple[bool, str, dict]:
    """返回 (ok, reason, payload)。"""
    payload = unpack(key, (token or "").strip())
    if not payload or payload.get("k") != KIND:
        return False, "invalid", {}
    if str(payload.get("sk") or "") != sitekey:
        return False, "bad_sitekey", payload
    if int(payload.get("exp") or 0) <= time.time():
        return False, "expired", payload
    if bind_ip and not hmac.compare_digest(str(payload.get("ip") or ""),
                                           ip_fingerprint(ip)):
        return False, "bad_ip", payload
    if bind_ua and not hmac.compare_digest(str(payload.get("ua") or ""),
                                           ua_fingerprint(ua)):
        return False, "bad_ua", payload
    return True, "ok", payload
