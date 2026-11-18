"""PelaCustoms 的 HTTP 接口。

对 nginx 只暴露三种语义（auth_request 只认这三种）：
    200 放行 / 401 需要质询 / 403 硬拒绝
其余一律用 JSON 接口给前端和运维用。
"""
from __future__ import annotations

import logging
import os
import re

from flask import (Blueprint, current_app, jsonify, make_response, redirect,
                   render_template, request, send_from_directory)

from .core import Engine, failure_message
from .matcher import normalize_path
from .version import __version__

log = logging.getLogger("pelacustoms.routes")

bp = Blueprint("pelacustoms", __name__, url_prefix="/__pc")

_HERE = os.path.dirname(os.path.abspath(__file__))
_STATIC = os.path.join(os.path.dirname(_HERE), "static", "pc")


def engine() -> Engine:
    return current_app.extensions["pc_engine"]


def state():
    return current_app.extensions["pc_state"]


def client_ip() -> str:
    fwd = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return fwd or (request.headers.get("X-Real-IP") or "").strip() or \
        (request.remote_addr or "")


def req_host() -> str:
    return (request.headers.get("X-Forwarded-Host")
            or request.headers.get("Host") or "").strip()


def client_ua() -> str:
    return (request.headers.get("User-Agent") or "").strip()


def request_id() -> str:
    """取 nginx 的 $request_id（由 X-Request-ID 头传进来）。

    刻意**不**自己生成：这个值必须同时出现在 access log 里才有意义。
    没传就返回空串，页面上整项不显示 —— 不摆一个查不到东西的装饰。
    """
    raw = (request.headers.get("X-Request-ID") or "").strip()
    if not raw:
        return ""
    return re.sub(r"[^A-Za-z0-9._-]", "", raw)[:64]


def _site():
    cfg = engine().cfg
    return cfg.for_host(req_host())


def _cookie_for(site, names: list[str]) -> str | None:
    if site is not None:
        names = [site.clearance.name] + names
    for n in names:
        v = request.cookies.get(n)
        if v:
            return v
    return None


def _apply_decision_headers(resp, decision):
    for k, v in decision.headers().items():
        resp.headers[k] = v
    return resp


# ============================================================
# 判定点：nginx auth_request 打这里
# ============================================================
@bp.route("/auth", methods=["GET", "POST"])
def auth():
    uri = (request.headers.get("X-Original-URI")
           or request.headers.get("X-Forwarded-URI") or "/")
    method = (request.headers.get("X-Original-Method") or request.method or "GET").upper()
    site = _site()
    names = ["pc_clearance"]
    dec = engine().decide(
        host=req_host(), method=method, uri=uri,
        cookie=_cookie_for(site, names), ip=client_ip(), ua=client_ua(),
        risk=request.headers.get(_risk_header_name()) or "",
    )
    # nginx 只认 200 / 401 / 403；其余一律会被翻成 500，所以这里绝不返回别的东西
    status = dec.status if dec.status in (200, 401, 403) else 401
    resp = make_response("", status)
    return _apply_decision_headers(resp, dec)


def _risk_header_name() -> str:
    site = _site()
    return site.challenge.risk_header if site is not None else "X-PC-Risk"


# ============================================================
# 质询页
# ============================================================
@bp.get("/challenge")
def challenge_page():
    site = _site()
    cfg = engine().cfg

    if site is None or not site.enabled:
        # 没有配站点：不拦人，放回原地址 —— 但同样要过白名单，
        # 否则「没配站点」就成了一个干净的开放重定向。
        return redirect(engine().safe_redirect(cfg, _original_uri(), site))

    ip = client_ip()
    if not state().rate_ok("page:" + ip, 5, 10.0):
        return _error_page("请求过于频繁，请稍后再试", 429)

    # 唯一出口：原始地址无论从 header 还是 rd 参数来，都先过白名单
    target = engine().safe_redirect(cfg, _original_uri(), site)
    method = (request.headers.get("X-Original-Method") or "").upper() or "GET"
    page = engine().issue_page(
        site=site, path=normalize_path(target), method=method, ip=ip,
        ua=client_ua(), risk=request.headers.get(site.challenge.risk_header) or "",
        redirect_url=target,
    )

    resp = make_response(render_template(
        "challenge.html", page=page, cfg=cfg,
        host=req_host(), trace=request_id(), version=__version__))
    _hardening(resp)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


def _original_uri() -> str:
    """原始地址从哪来：nginx 的 header 优先，其次 rd 参数，最后退到 /。"""
    raw = (request.headers.get("X-PC-Original-URI")
           or request.headers.get("X-Original-URI")
           or request.args.get("rd") or "/")
    if not raw.startswith("/"):
        # 防御性保留：即便上游传了绝对地址，也要先过 safe_redirect 白名单
        return raw
    return raw


def _hardening(resp):
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Cache-Control", "no-store")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'none'; script-src 'self'; worker-src 'self' blob:; "
        "style-src 'self'; img-src 'self' data:; connect-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    return resp


def _error_page(message: str, status: int):
    html = ("<!doctype html><meta charset=utf-8>"
            "<title>PelaCustoms</title>"
            "<style>html,body{height:100%;margin:0;background:#000;color:#f0f0f0;"
            "display:flex;align-items:center;justify-content:center;"
            "font:13px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,"
            "'PingFang SC','Microsoft YaHei',sans-serif}"
            "div{border:1px solid #3c3c3c;border-radius:2px;padding:18px 22px;"
            "max-width:344px;text-align:center}</style>"
            "<div>" + message + "</div>")
    resp = make_response(html, status)
    return _hardening(resp)


# ============================================================
# 验证并发放通行证
# ============================================================
@bp.post("/verify")
def verify():
    site = _site()
    if site is None or not site.enabled:
        return jsonify({"ok": False, "reason": "unknown_site",
                        "message": "站点未配置"}), 400

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        body = request.form.to_dict() if request.form else {}

    ok, reason, value, ttl, level = engine().verify(
        site=site, body=body, ip=client_ip(), ua=client_ua())

    if not ok:
        state().record(False, reason, site.sitekey)
        return jsonify({"ok": False, "reason": reason,
                        "message": failure_message(reason)}), 403

    resp = jsonify({"ok": True, "level": level, "ttl": int(ttl),
                    "reload": True})
    secure = site.clearance.secure and _is_secure_request()
    resp.set_cookie(
        site.clearance.name, value,
        max_age=int(ttl), path=site.clearance.path,
        domain=site.clearance.domain or None,
        secure=secure, httponly=site.clearance.http_only,
        samesite=site.clearance.same_site,
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _is_secure_request() -> bool:
    if request.is_secure:
        return True
    proto = (request.headers.get("X-Forwarded-Proto") or "").lower()
    if proto:
        return proto == "https"
    # 本地 http 调试时不要设 Secure，否则浏览器根本不回传 cookie
    host = req_host().split(":")[0].lower()
    return host not in ("127.0.0.1", "localhost", "::1", "")


# ============================================================
# 静态资源 / 运维
# ============================================================
@bp.get("/static/<path:filename>")
def static_file(filename: str):
    resp = make_response(send_from_directory(_STATIC, filename))
    if filename.endswith(".js"):
        resp.headers["Content-Type"] = "application/javascript; charset=utf-8"
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


@bp.get("/healthz")
def healthz():
    cfg = engine().cfg
    return jsonify({
        "ok": True,
        "configured": cfg.server.configured,
        "degraded": bool(current_app.extensions.get("pc_config_error")),
        "error": current_app.extensions.get("pc_config_error") or "",
        "mode": "proxy" if cfg.server.proxy_mode else "hosted",
        "sites": sorted(cfg.sites),
        "warnings": list(cfg.warnings),
        "last": state().last_result,
    })


@bp.get("/api/v1/config")
def public_config():
    """公开配置：给自定义前端和运维排查用，不含任何秘密。"""
    site = _site()
    if site is None:
        return jsonify({"ok": False, "reason": "unknown_site"}), 404
    return jsonify({
        "ok": True,
        "sitekey": site.sitekey,
        "enabled": site.enabled,
        "protect": {"paths": site.protect.paths, "exclude": site.protect.exclude,
                    "methods": site.protect.methods},
        "clearance": {"name": site.clearance.name, "ttl": site.clearance.ttl,
                      "ttl_by_level": {str(k): v for k, v in
                                       site.clearance.ttl_by_level.items()}},
        "challenge": {"level": site.challenge.level,
                      "page_ttl": site.challenge.page_ttl,
                      "difficulty": site.challenge.difficulty,
                      "prefix": site.challenge.prefix},
        "mode": "proxy" if engine().cfg.server.proxy_mode else "hosted",
    })
