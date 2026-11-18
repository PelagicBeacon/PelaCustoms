"""PelaCustoms 自检。没有 pytest 也能跑：

    python tests/test_flow.py

覆盖三块：URI 归一化（最容易出漏洞的地方）、配置校验（写坏不能把站打挂）、
完整准入流程（质询 → PoW → 通行证 → 放行）。
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["PC_SECRET"] = "test-secret-0123456789abcdef"

from pelacustoms import create_app                              # noqa: E402
from pelacustoms.clearance import pack                           # noqa: E402
from pelacustoms.config import ConfigError, parse_duration       # noqa: E402
from pelacustoms.matcher import PatternSet, normalize_path       # noqa: E402

TESTS: list = []


def test(fn):
    TESTS.append(fn)
    return fn


# ============================================================
# 归一化 —— 这一段是安全边界，别删用例
# ============================================================
@test
def normalization_blocks_traversal():
    assert normalize_path("/admin/../public") == "/public"
    assert normalize_path("/admin/%2e%2e/public") == "/public"
    assert normalize_path("/admin/%2E%2E/%2e%2e/etc") == "/etc"
    assert normalize_path("//admin///x//") == "/admin/x"
    assert normalize_path("/a/b/") == "/a/b"
    assert normalize_path("/a/b?x=/admin&y=1") == "/a/b"
    assert normalize_path("/%61dmin") == "/admin"      # 解码后再判
    assert normalize_path("") == "/"
    assert normalize_path("/") == "/"


@test
def normalization_keeps_case():
    """大小写敏感：不做小写化，免得和上游路由规则打架。"""
    assert normalize_path("/Admin") == "/Admin"
    assert normalize_path("/admin") != normalize_path("/Admin")


@test
def glob_semantics():
    all_paths = PatternSet(["/**"])
    assert all_paths.matches("/")
    assert all_paths.matches("/a/b/c")

    admin = PatternSet(["/admin/**"])
    assert admin.matches("/admin")
    assert admin.matches("/admin/users")
    assert not admin.matches("/administrator")       # 前缀不等于目录
    assert not admin.matches("/x/admin")

    single = PatternSet(["/static/*.js"])
    assert single.matches("/static/app.js")
    assert not single.matches("/static/deep/app.js")  # * 不跨目录

    dbl = PatternSet(["/static/**/*.js"])
    assert dbl.matches("/static/app.js")              # **/ 允许零级目录
    assert dbl.matches("/static/deep/app.js")

    rx = PatternSet(["re:^/admin/[0-9]+$"])
    assert rx.matches("/admin/42")
    assert not rx.matches("/admin/abc")


# ============================================================
# 配置
# ============================================================
@test
def durations():
    assert parse_duration("30m", "t") == 1800
    assert parse_duration("90s", "t") == 90
    assert parse_duration("2h", "t") == 7200
    assert parse_duration(45, "t") == 45          # 裸数字就是秒
    assert parse_duration("1.5h", "t") == 5400
    for bad in ("abc", "", "-5m", "30x"):
        try:
            parse_duration(bad, "t")
        except ConfigError:
            pass
        else:
            raise AssertionError("应当拒绝时长 " + repr(bad))


BASE_TOML = """
[server]
listen = "127.0.0.1:8090"
fail_mode = "closed"

[defaults.protect]
paths   = ["/**"]
exclude = ["/__pc/**", "/static/**", "/public/**"]

[defaults.clearance]
secure = false
ttl    = "10m"

[defaults.challenge]
difficulty = 1
page_ttl   = "90s"

[sites."*"]
sitekey = "t"
enabled = true
"""


def _write(text: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".toml", text=True)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def make_app(extra: str = ""):
    return create_app(_write(BASE_TOML + extra), watch=False)


@test
def config_rejects_bad_values():
    for extra in ('\n[sites."*".clearance]\nttl = "abc"\n',
                  '\n[sites."*".challenge]\nlevel = "9"\n',
                  '\n[sites."*".clearance]\nnope = 1\n',
                  '\n[defaults.protect]\nmethods = 5\n'):
        try:
            make_app(extra)
        except ConfigError:
            continue
        raise AssertionError("应当拒绝这段配置：" + extra.strip())


@test
def config_keeps_previous_on_error():
    from pelacustoms.config import ConfigStore
    path = _write(BASE_TOML)
    store = ConfigStore(path)
    first = store.get()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("[server\nbroken toml")
    assert store.reload() is False
    assert store.last_error
    assert store.get() is first, "配置写坏时必须继续用上一份"


# ============================================================
# 完整流程
# ============================================================
def _auth(client, uri="/", method="GET", **extra):
    headers = {"X-Original-URI": uri, "X-Original-Method": method}
    headers.update(extra)
    return client.get("/__pc/auth", headers=headers)


def _pend(client, uri="/", method="GET"):
    r = client.get("/__pc/challenge",
                   headers={"X-PC-Original-URI": uri, "X-Original-Method": method})
    assert r.status_code == 200, r.status_code
    html = r.get_data(as_text=True)
    pend = re.search(r'data-pend="([^"]+)"', html).group(1)
    chal = re.search(r'data-challenge="([^"]+)"', html).group(1)
    prefix = int(re.search(r'data-prefix="(\d+)"', html).group(1))
    return pend, chal, prefix


def _solve(chal, prefix):
    n = 0
    while not hashlib.sha256((chal + ":" + str(n)).encode()).hexdigest().startswith("0" * prefix):
        n += 1
    return n


@test
def full_flow():
    app = make_app()
    c = app.test_client()

    assert _auth(c).status_code == 401, "没票就该 401"

    pend, chal, prefix = _pend(c, "/secret")
    assert prefix >= 3
    nonce = _solve(chal, prefix)

    r = c.post("/__pc/verify", json={
        "pend": pend, "nonce": nonce, "pointer_type": "auto", "hold_ms": 0,
        "path": [], "features": {"ua": "Mozilla/5.0 (Windows NT 10.0) Chrome/131.0",
                                 "webdriver": False, "chrome": True,
                                 "plugins": 5, "languages": 2,
                                 "hardware": 8, "depth": 24, "screen_w": 1920},
    })
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()["ok"] is True
    assert r.headers["Set-Cookie"].startswith("pc_clearance=")

    after = _auth(c)
    assert after.status_code == 200, "拿到通行证后应当放行"
    assert after.headers["X-PC-Reason"] == "cleared"


@test
def deny_header_marks_a_challenge_not_a_backend_401():
    """X-PC-Deny 只在拒绝时出现。

    API 模式靠它把「判定子请求拒绝」和「后端自己返回的 401」分开：
    混为一谈的话，应用层的登录过期会被误认成需要质询，前端绕过质询后
    重试仍是 401，再次触发质询，形成死循环。
    """
    c = make_app().test_client()

    denied = _auth(c, "/api/search", "POST")
    assert denied.status_code == 401
    assert denied.headers.get("X-PC-Deny") == "1"

    # 放行时不能带这个头，否则后端自己的 401 前端也会误判
    allowed = _auth(c, "/public/ping")
    assert allowed.status_code == 200
    assert "X-PC-Deny" not in allowed.headers


@test
def excluded_paths_never_challenge():
    app = make_app()
    c = app.test_client()
    for uri in ("/static/app.js", "/public/ping", "/__pc/healthz"):
        assert _auth(c, uri).status_code == 200, uri


@test
def wrong_nonce_is_rejected_but_not_fatal():
    app = make_app()
    c = app.test_client()
    pend, chal, prefix = _pend(c, "/x")
    good = _solve(chal, prefix)
    bad = 0 if good != 0 else 1

    r = c.post("/__pc/verify", json={"pend": pend, "nonce": bad,
                                     "pointer_type": "auto", "hold_ms": 0,
                                     "path": [], "features": {}})
    assert r.status_code == 403
    assert r.get_json()["reason"] == "wrong"

    r2 = c.post("/__pc/verify", json={"pend": pend, "nonce": good,
                                      "pointer_type": "auto", "hold_ms": 0,
                                      "path": [], "features": {}})
    assert r2.status_code == 200, "先验答案再记账：算错不该烧掉质询票"


@test
def automation_is_rejected():
    app = make_app()
    c = app.test_client()
    pend, chal, prefix = _pend(c, "/x")
    n = _solve(chal, prefix)
    r = c.post("/__pc/verify", json={"pend": pend, "nonce": n,
                                     "pointer_type": "auto", "hold_ms": 0,
                                     "path": [], "features": {"webdriver": True}})
    assert r.status_code == 403
    assert r.get_json()["reason"] == "automation"


@test
def synthetic_pointer_is_rejected():
    app = make_app()
    c = app.test_client()
    pend, chal, prefix = _pend(c, "/x")
    n = _solve(chal, prefix)
    r = c.post("/__pc/verify", json={"pend": pend, "nonce": n,
                                     "pointer_type": "synthetic", "hold_ms": 0,
                                     "path": [], "features": {}})
    assert r.get_json()["reason"] == "automation"


@test
def post_requires_click_gate():
    """非安全方法 → L2 → 必须有过得去的点击轨迹。"""
    app = make_app()
    c = app.test_client()
    pend, chal, prefix = _pend(c, "/submit", method="POST")
    n = _solve(chal, prefix)

    r = c.post("/__pc/verify", json={"pend": pend, "nonce": n,
                                     "pointer_type": "auto", "hold_ms": 0,
                                     "path": [], "features": {}})
    assert r.get_json()["reason"] == "interaction", "跳过关卡直接交答案应当被拒"

    r2 = c.post("/__pc/verify", json={
        "pend": pend, "nonce": n, "pointer_type": "mouse", "hold_ms": 80,
        "path": [[10, 10, 0], [120, 40, 90], [240, 30, 160], [300, 60, 220]],
        "features": {}})
    assert r2.status_code == 200, r2.get_data(as_text=True)


@test
def expired_pend_is_rejected():
    app = make_app()
    c = app.test_client()
    engine = app.extensions["pc_engine"]
    site = engine.cfg.for_host("localhost")
    pend = pack(engine._key(site), {
        "k": "pend", "sk": site.sitekey, "chal": "a" * 8, "pfx": 3, "lvl": 1,
        "p": "/", "m": "GET", "ip": "", "ua": "", "exp": int(time.time()) - 10,
    })
    r = c.post("/__pc/verify", json={"pend": pend, "nonce": 0,
                                     "pointer_type": "auto", "hold_ms": 0,
                                     "path": [], "features": {}})
    assert r.get_json()["reason"] == "expired"


@test
def tampered_cookie_is_rejected():
    app = make_app()
    c = app.test_client()
    c.set_cookie("pc_clearance", "eyJrIjoiY2xlYXIifQ.deadbeef")
    assert _auth(c).status_code == 401


@test
def crawler_ua_passes():
    app = make_app()
    c = app.test_client()
    r = _auth(c, "/", **{"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"})
    assert r.status_code == 200
    assert r.headers["X-PC-Reason"] == "crawler"


@test
def disabled_site_passes_everything():
    app = make_app('\n[sites."off.example"]\nsitekey = "off"\nenabled = false\n')
    c = app.test_client()
    r = c.get("/__pc/auth", headers={"X-Original-URI": "/", "Host": "off.example"})
    assert r.status_code == 200


@test
def challenge_page_never_redirects_offsite():
    """rd 参数是攻击者可控的：它不能让质询页变成开放重定向。"""
    app = make_app()
    c = app.test_client()
    for evil in ("https://evil.example.com/x", "//evil.example.com/x",
                 "http://evil.example.com", "javascript:alert(1)",
                 "data:text/html,<script>alert(1)</script>"):
        r = c.get("/__pc/challenge?rd=" + evil)
        assert r.status_code == 200, evil
        html = r.get_data(as_text=True)
        m = re.search(r'data-redirect="([^"]*)"', html)
        assert m, "质询页应当带 data-redirect"
        got = m.group(1)
        assert "evil.example.com" not in got and "javascript:" not in got \
            and "data:" not in got, "非本站地址被写进了回跳目标：" + got

    # 相对路径要正常保留（换一个 app，避开每 IP 10 秒 5 次的质询页限流）
    c2 = make_app().test_client()
    r = c2.get("/__pc/challenge?rd=/admin/users?tab=1")
    got = re.search(r'data-redirect="([^"]*)"', r.get_data(as_text=True)).group(1)
    assert got == "/admin/users?tab=1", got


@test
def safe_redirect_whitelist():
    app = make_app('\n[sites."ok.example"]\nsitekey = "ok2"\nenabled = true\n')
    eng = app.extensions["pc_engine"]
    cfg = eng.cfg
    site = cfg.for_host("ok.example")
    assert eng.safe_redirect(cfg, "/a?b=1", site) == "/a?b=1"
    assert eng.safe_redirect(cfg, "//evil.com/a", site) == "/"
    assert eng.safe_redirect(cfg, "javascript:alert(1)", site) == "/"
    assert eng.safe_redirect(cfg, "https://evil.com", site) == "/"
    assert eng.safe_redirect(cfg, "https://ok.example/x", site) == "https://ok.example/x"
    assert eng.safe_redirect(cfg, "", site) == "/"


FULL_HEAD = """
[server]
listen = "127.0.0.1:8090"
fail_mode = "closed"
"""


def make_app_full(text: str):
    """整份配置自己写，用来构造 [server] 级别的危险组合。"""
    return create_app(_write(text), watch=False)


@test
def request_id_only_when_upstream_provides_it():
    """页面上的请求 ID 必须和 access log 对得上，所以只认 nginx 传的。"""
    app = make_app()
    c = app.test_client()

    plain = c.get("/__pc/challenge").get_data(as_text=True)
    assert "请求 ID" not in plain, "没传 X-Request-ID 时不该显示这一项"
    assert "v0.1.0" in plain

    withrid = c.get("/__pc/challenge",
                    headers={"X-Request-ID": "a1b2c3d4e5f6"}).get_data(as_text=True)
    assert "请求 ID a1b2c3d4e5f6" in withrid

    # 恶意字符被过滤，不会进 HTML 也不会进日志
    dirty = c.get("/__pc/challenge",
                  headers={"X-Request-ID": "<script>x</script> 7f"}).get_data(as_text=True)
    assert "<script>x</script>" not in dirty
    assert "请求 ID scriptxscript7f" in dirty


@test
def challenge_page_satisfies_widget_contract():
    """页面必须真的把脚本引进来，并且带齐 JS 要用的每个 id。

    这条是补的：早先模板被重写后丢了 <script> 那行，页面只剩 CSS 在转圈，
    而所有断言 data-* 的用例全部照过 —— 到真实浏览器里才发现。
    """
    app = make_app()
    html = app.test_client().get("/__pc/challenge").get_data(as_text=True)

    assert "/__pc/static/customs.js" in html, "模板必须引入质询脚本"
    assert "/__pc/static/customs.css" in html, "模板必须引入样式"

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    js = open(os.path.join(root, "static", "pc", "customs.js"), encoding="utf-8").read()
    assert "/__pc/static/customs-worker.js" in js, "JS 必须引用 PoW worker"

    ids = set(re.findall(r"getElementById\('([^']+)'\)", js))
    assert ids, "JS 应当通过 id 取元素"
    for one in sorted(ids):
        assert ('id="' + one + '"') in html, "页面缺少 JS 依赖的元素 id=" + one


@test
def hosted_mode_is_refused_with_a_reason():
    """托管模式跑不通（cookie 落不到业务域），所以必须拒绝而不是静默降级。"""
    try:
        make_app_full(FULL_HEAD + 'public_origin = "https://c.example.com"\n'
                      + '\n[sites."*"]\nsitekey = "t"\nenabled = true\n')
    except ConfigError as exc:
        assert "托管模式尚未实现" in str(exc), str(exc)
    else:
        raise AssertionError("设置 public_origin 时应当拒绝启动")


@test
def config_audit_warns_on_public_listen():
    app = make_app_full('[server]\nlisten = "0.0.0.0:8090"\nfail_mode = "closed"\n'
                        '\n[sites."*"]\nsitekey = "t"\nenabled = false\n')
    warns = app.extensions["pc_engine"].cfg.warnings
    assert any("不是回环地址" in w for w in warns), warns


@test
def strict_config_refuses_to_start():
    os.environ["PC_STRICT_CONFIG"] = "1"
    try:
        try:
            make_app_full('[server]\nlisten = "0.0.0.0:8090"\n')
        except ConfigError:
            pass
        else:
            raise AssertionError("PC_STRICT_CONFIG=1 时应当拒绝启动")
    finally:
        os.environ.pop("PC_STRICT_CONFIG", None)


@test
def unconfigured_secret_fails_closed():
    os.environ["PC_SECRET"] = "short"
    try:
        app = make_app()
        c = app.test_client()
        assert _auth(c).status_code == 403, "没有强密钥时必须拒绝，而不是放行"
    finally:
        os.environ["PC_SECRET"] = "test-secret-0123456789abcdef"


# ============================================================
# 中间件
# ============================================================
@test
def middleware_logs_the_request_id_it_shows():
    """页面上显示的 ID 必须真的写进日志，否则它就是个装饰。"""
    import logging

    records = []

    class Grab(logging.Handler):
        def emit(self, record):
            records.append(record)

    from werkzeug.test import Client
    from werkzeug.wrappers import Response
    from pelacustoms.middleware import CustomsMiddleware

    def inner(environ, start_response):
        return Response("ok", status=200)(environ, start_response)

    app = make_app()
    client = Client(CustomsMiddleware(app, inner))

    lg = logging.getLogger("pelacustoms.middleware")
    handler = Grab()
    lg.addHandler(handler)
    lg.setLevel(logging.INFO)
    try:
        body = client.get("/secret").get_data(as_text=True)
    finally:
        lg.removeHandler(handler)

    m = re.search(r"请求 ID ([0-9a-f]+)", body)
    assert m, "页面应当带上中间件生成的请求 ID"
    assert records, "必须写出日志，否则页面上这个 ID 查不到任何东西"
    assert m.group(1) in records[-1].getMessage(), "日志里的 ID 要和页面上的一致"


@test
def middleware_serves_challenge_instead_of_403():
    from werkzeug.test import Client
    from werkzeug.wrappers import Response

    def inner(environ, start_response):
        return Response("backend-ok", status=200)(environ, start_response)

    from pelacustoms.middleware import CustomsMiddleware
    app = make_app()
    client = Client(CustomsMiddleware(app, inner))

    r = client.get("/secret")
    assert r.status_code == 200
    assert "data-pend" in r.get_data(as_text=True), "被拦时应当顶上质询页"

    r2 = client.get("/public/ping")
    assert r2.get_data(as_text=True) == "backend-ok"


# ============================================================
# 运行器
# ============================================================
def main() -> int:
    passed = failed = 0
    for fn in TESTS:
        try:
            fn()
        except Exception as exc:                       # noqa: BLE001
            failed += 1
            print("FAIL  " + fn.__name__ + "\n        " + type(exc).__name__ + ": " + str(exc))
        else:
            passed += 1
            print("ok    " + fn.__name__)
    print("")
    print(str(passed) + " passed, " + str(failed) + " failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())