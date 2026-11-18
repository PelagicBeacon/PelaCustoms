"""WSGI 中间件模式：没有 nginx 也能用，或者本地联调时少起一个进程。

它做的事情和 nginx 的 auth_request 完全一样——判定，然后要么放行到内层应用，
要么把质询页顶上去。区别只是不走网络、不开子请求。

用法：
    from werkzeug.middleware.dispatcher import DispatcherMiddleware
    app = CustomsMiddleware(customs_app, my_flask_app)
    app = DispatcherMiddleware(app)      # 这样 /__pc/* 也能被 customs_app 接住
"""
from __future__ import annotations

import logging
import secrets
from urllib.parse import quote

from .matcher import normalize_path

log = logging.getLogger("pelacustoms.middleware")


class CustomsMiddleware:
    def __init__(self, customs_app, inner_app, prefix: str = "/__pc"):
        self.customs = customs_app
        self.inner = inner_app
        self.prefix = prefix

    # ---------------------------------------------------------- WSGI
    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO") or "/"
        if path.startswith(self.prefix):
            return self.customs(environ, start_response)

        engine = self.customs.extensions["pc_engine"]
        host = (environ.get("HTTP_X_FORWARDED_HOST")
                or environ.get("HTTP_HOST") or "")
        method = environ.get("REQUEST_METHOD", "GET").upper()
        uri = environ.get("RAW_URI") or path
        if environ.get("QUERY_STRING"):
            uri = uri + "?" + environ["QUERY_STRING"]

        site = engine.cfg.for_host(host)
        cookie_name = site.clearance.name if site is not None else "pc_clearance"
        cookie = environ.get("HTTP_COOKIE") or ""
        value = _cookie_value(cookie, cookie_name)

        ip = (environ.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
              or environ.get("HTTP_X_REAL_IP", "")
              or environ.get("REMOTE_ADDR", ""))
        ua = environ.get("HTTP_USER_AGENT", "")
        risk = ""
        if site is not None:
            key = "HTTP_" + site.challenge.risk_header.upper().replace("-", "_")
            risk = environ.get(key, "")

        decision = engine.decide(host=host, method=method, uri=uri, cookie=value,
                                 ip=ip, ua=ua, risk=risk)

        if decision.allow:
            return self.inner(environ, start_response)

        # 被拦：把质询页当成这次请求的响应，浏览器地址栏不动
        page_env = dict(environ)
        page_env["PATH_INFO"] = self.prefix + "/challenge"
        page_env["SCRIPT_NAME"] = ""
        page_env["REQUEST_METHOD"] = "GET"
        page_env["QUERY_STRING"] = "rd=" + quote(path, safe="/")
        page_env["HTTP_X_PC_ORIGINAL_URI"] = path
        page_env["HTTP_X_ORIGINAL_METHOD"] = method
        # 中间件模式没有 nginx 注入 $request_id，这里自己发一个并记日志，
        # 保证页面上那个 ID 真的能查得到。
        rid = environ.get("HTTP_X_REQUEST_ID") or secrets.token_hex(6)
        page_env["HTTP_X_REQUEST_ID"] = rid
        log.info("拦截 rid=%s %s %s site=%s level=%d",
                 rid, method, path, decision.sitekey, decision.level)
        out = []
        status_holder = {}

        def _capture(status, headers, exc_info=None):
            status_holder["status"] = status
            status_holder["headers"] = headers
            return out.append

        body = self.customs(page_env, _capture)
        start_response("200 OK", _filter_headers(status_holder.get("headers", [])))
        return body


def _cookie_value(raw: str, name: str) -> str | None:
    for part in raw.split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k.strip() == name:
            return v.strip()
    return None


def _filter_headers(headers):
    drop = {"content-length", "transfer-encoding", "connection"}
    return [(k, v) for k, v in headers if k.lower() not in drop]
