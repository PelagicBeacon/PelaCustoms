"""PelaCustoms —— 托管的整页人机质询（来源可得许可，见 LICENSE）。"""
from __future__ import annotations

import logging
import os

from flask import Flask

from .config import ConfigStore, load_config
from .core import Engine
from .routes import bp
from .store import MemoryStore

from .version import __version__

__all__ = ["create_app", "Engine", "ConfigStore"]

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def create_app(config_path: str | None = None, *, store: ConfigStore | None = None,
               watch: bool = True) -> Flask:
    logging.basicConfig(
        level=os.getenv("PC_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    path = config_path or os.getenv("PC_CONFIG") or os.path.join(_ROOT, "customs.toml")
    store = store or ConfigStore(path)
    if watch:
        store.start()

    app = Flask(__name__,
                static_folder=os.path.join(_ROOT, "static"),
                static_url_path="/static",
                template_folder=os.path.join(_ROOT, "templates"))
    app.config["PC_CONFIG_PATH"] = path

    state = MemoryStore()
    app.extensions["pc_config_store"] = store
    app.extensions["pc_engine"] = Engine(store.get(), state)
    app.extensions["pc_state"] = state
    app.extensions["pc_config_error"] = store.last_error

    app.register_blueprint(bp)

    @app.get("/")
    def index():
        cfg = store.get()
        return {
            "name": "PelaCustoms",
            "version": __version__,
            "mode": "proxy" if cfg.server.proxy_mode else "hosted",
            "configured": cfg.server.configured,
            "sites": sorted(cfg.sites),
            "endpoints": ["/__pc/auth", "/__pc/challenge", "/__pc/verify",
                          "/__pc/healthz", "/__pc/api/v1/config"],
        }

    @app.teardown_appcontext
    def _refresh(_exc):
        # 配置热载后引擎要换到新配置；id 变了才换，避免每请求都重建
        cur = store.get()
        eng = app.extensions["pc_engine"]
        if eng.cfg is not cur:
            app.extensions["pc_engine"] = Engine(cur, state)
        app.extensions["pc_config_error"] = store.last_error

    @app.after_request
    def _global_headers(resp):
        resp.headers.setdefault("X-PC-Version", __version__)
        return resp

    return app
