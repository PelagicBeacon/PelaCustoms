"""本地演示：一个假的业务站 + PelaCustoms，用 WSGI 中间件串起来。

    python demo.py
    # 打开 http://127.0.0.1:8091/

这样不用装 nginx 也能看到完整的整页质询流程。真实部署仍然建议走
nginx 的 auth_request（见 deploy/nginx.conf.sample），中间件更适合
没法改 nginx 的场景。
"""
from __future__ import annotations

import os
import sys

os.environ.setdefault("PC_SECRET", "demo-secret-do-not-use-in-production-32")
os.environ.setdefault("PC_CONFIG",
                      os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "demo", "customs.demo.toml"))

from flask import Flask, request  # noqa: E402

from pelacustoms import create_app  # noqa: E402
from pelacustoms.middleware import CustomsMiddleware  # noqa: E402

SITE_HTML = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>演示站点 · 由 PelaCustoms 守着</title>
<style>
  html,body{height:100%;margin:0;background:#0a0a0a;color:#e8e8e8;
    font:14px/1.65 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,
    'PingFang SC','Microsoft YaHei',sans-serif}
  main{max-width:560px;margin:0 auto;padding:64px 24px}
  h1{font-size:20px;font-weight:600;letter-spacing:.3px;margin:0 0 6px}
  p.lead{color:#8a8a8a;margin:0 0 28px;font-size:13px}
  .card{border:1px solid #2c2c2c;border-radius:2px;padding:18px;margin-bottom:14px}
  .card h2{font-size:12px;text-transform:uppercase;letter-spacing:1.2px;
    color:#8a8a8a;margin:0 0 10px;font-weight:600}
  a{color:#4e8ee0;text-decoration:none;border-bottom:1px dotted rgba(78,142,224,.5)}
  a:hover{border-bottom-style:solid}
  input{width:100%;box-sizing:border-box;background:#111;border:1px solid #333;
    border-radius:2px;color:#eee;padding:9px 11px;font:inherit;margin-bottom:10px}
  button{background:transparent;border:1px solid #4e8ee0;color:#eee;border-radius:2px;
    padding:9px 20px;font:inherit;cursor:pointer}
  button:hover{background:rgba(78,142,224,.12)}
  .ok{color:#2ea868}
  code{background:#141414;border:1px solid #262626;border-radius:2px;padding:1px 5px;
    font-size:12px}
</style></head><body><main>
  <h1>演示站点</h1>
  <p class="lead">这一页在 PelaCustoms 的保护范围内。第一次访问应该先看到整页质询。</p>
  <div class="card">
    <h2>1 · 提交点</h2>
    <p style="margin:0 0 12px;color:#8a8a8a;font-size:13px">
      POST 属于非安全方法，默认走 L2（需要点击）。</p>
    <form method="post" action="/submit">
      <input name="note" placeholder="随便写点什么" value="hello">
      <button type="submit">提交</button>
    </form>
  </div>
  <div class="card">
    <h2>2 · 不受保护的路径</h2>
    <p style="margin:0;color:#8a8a8a;font-size:13px">
      <a href="/public/ping">/public/ping</a> 在 exclude 名单里，永远不质询。</p>
  </div>
  <div class="card">
    <h2>3 · 看看判定结果</h2>
    <p style="margin:0;color:#8a8a8a;font-size:13px">
      <a href="/__pc/healthz">/__pc/healthz</a> ·
      <a href="/__pc/api/v1/config">/__pc/api/v1/config</a></p>
  </div>
</main></body></html>"""

site = Flask("demo_site")


@site.get("/")
def home():
    return SITE_HTML


@site.post("/submit")
def submit():
    note = (request.form.get("note") or "").strip()
    return ("<!doctype html><meta charset=utf-8>"
            "<body style=\"background:#0a0a0a;color:#e8e8e8;"
            "font:14px/1.7 -apple-system,'PingFang SC',sans-serif;padding:64px\">"
            "<p class=ok>提交成功 —— 说明这次 POST 已经带着通行证穿过了海关。</p>"
            "<p style=color:#8a8a8a>你写的是：" + (note or "(空)") + "</p>"
            "<p><a style=color:#4e8ee0 href=/>回去</a></p>")


@site.get("/public/ping")
def ping():
    return {"ok": True, "protected": False}


customs = create_app()
app = CustomsMiddleware(customs, site)


if __name__ == "__main__":
    cfg = customs.extensions["pc_config_store"].get()
    print("PelaCustoms 演示 → http://127.0.0.1:8091/")
    print("站点：", sorted(cfg.sites), " 模式：",
          "proxy" if cfg.server.proxy_mode else "hosted")
    if not cfg.server.configured:
        print("!! 没有可用密钥，拒绝签票", file=sys.stderr)
    app = CustomsMiddleware(customs, site)
    from werkzeug.serving import run_simple
    run_simple("127.0.0.1", 8091, app, use_reloader=False)
