"""真实 HTTP 冒烟测试：需要先另起一个进程跑 demo.py。

    python demo.py            # 终端 1
    python tests/smoke_http.py  # 终端 2

走的是浏览器同一条路径：拿质询页 → 算 PoW → 换通行证 → 再访问业务页。
默认打 http://127.0.0.1:8091，可用 PC_BASE 覆盖。
"""
import hashlib
import http.cookiejar
import json
import os
import re
import urllib.error
import urllib.request

BASE = os.getenv("PC_BASE", "http://127.0.0.1:8091")
jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def get(path, headers=None):
    req = urllib.request.Request(BASE + path, headers=headers or {})
    try:
        with op.open(req) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main() -> int:
    status, body = get("/")
    assert status == 200 and "data-pend" in body, "第一次访问应当看到质询页"
    print("ok    质询页已下发")

    pend = re.search(r'data-pend="([^"]+)"', body).group(1)
    chal = re.search(r'data-challenge="([^"]+)"', body).group(1)
    pfx = int(re.search(r'data-prefix="(\d+)"', body).group(1))

    nonce = 0
    while not hashlib.sha256((chal + ":" + str(nonce)).encode()).hexdigest().startswith("0" * pfx):
        nonce += 1

    payload = json.dumps({
        "pend": pend, "nonce": nonce, "pointer_type": "auto", "hold_ms": 0,
        "path": [], "features": {
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0",
            "webdriver": False, "chrome": True, "plugins": 5, "languages": 2,
            "hardware": 8, "depth": 24, "screen_w": 1920},
    }).encode()
    req = urllib.request.Request(BASE + "/__pc/verify", data=payload,
                                 headers={"Content-Type": "application/json"})
    with op.open(req) as r:
        assert r.status == 200, r.status
    print("ok    PoW 通过，已签发通行证")

    assert [c.name for c in jar] == ["pc_clearance"], [c.name for c in jar]
    status, body = get("/")
    assert status == 200 and "data-pend" not in body, "带票后不该再看到质询页"
    print("ok    带票访问直接回源")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
