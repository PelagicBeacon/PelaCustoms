"""开发 / 生产入口：python app.py

生产部署（单进程，判定状态在内存里）：
    gunicorn -w 1 -b 127.0.0.1:8090 "app:app"
    waitress-serve --listen=127.0.0.1:8090 app:app

注意：PelaCustoms 只监听回环地址，由站点的 nginx 反向代理过来。
它自己不需要对外暴露，也不需要证书 —— TLS 在站点那一层终止。
"""
from __future__ import annotations

import os

from pelacustoms import create_app

app = create_app()

if __name__ == "__main__":
    host, _, port = (os.getenv("PC_LISTEN")
                     or app.extensions["pc_config_store"].get().server.listen).rpartition(":")
    app.run(host=host or "127.0.0.1", port=int(port or 8090),
            debug=os.getenv("PC_DEBUG") == "1")
