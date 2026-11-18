# PelaCustoms

自托管的人机验证服务，为 Nginx 提供请求级准入判定。
未通过判定的请求被替换为同源的整页质询界面，通过后签发限时通行证。

- 无数据库、无外部依赖，状态保存在进程内存
- 与站点同源部署，不需要独立域名、证书或 CORS 配置
- 通行证为 HMAC 签名的 cookie，判定时不访问共享存储

MIT 许可。

## 与 PelaReeflet 的关系

| | PelaReeflet | PelaCustoms |
| --- | --- | --- |
| 集成方式 | 页面内组件 | Nginx `auth_request` |
| 生效时机 | 表单提交时 | 每个受保护请求 |
| 凭据 | ticket，由业务后端核验 | clearance cookie，由判定点核验 |

两者共用同一套验证内核：浏览器环境探测、指针轨迹分析、SHA-256 工作量证明。

## 工作原理

1. 浏览器请求受保护资源。
2. Nginx 通过 `auth_request` 子请求向 `/__pc/auth` 查询判定结果。
3. 请求未携带有效通行证时，Nginx 以 `error_page` 将质询页渲染在当前域名下。
4. 质询页完成环境探测与工作量证明，调用 `/__pc/verify` 换取通行证。
5. 页面刷新，请求携带通行证再次到达，判定通过并回源。

```
GET / ──▶ nginx auth_request ──▶ /__pc/auth
                                  │ 200  放行，回源
                                  │ 401  需质询，error_page → /__pc/challenge
                                  │ 403  拒绝
                                          │
                            环境探测 → [点击关卡] → PoW
                                          │
                            POST /__pc/verify → Set-Cookie
                                          │
                            页面刷新 → 携带 cookie → 200
```

质询页由站点自身的 Nginx 在 `/__pc/` 路径下代理。因此通行证是第一方 cookie，
页面不发生跨域跳转，也不存在开放重定向风险。

## 质询级别

| 级别 | 触发条件 | 用户操作 | 通行证有效期 |
| --- | --- | --- | --- |
| L1 | 安全方法（GET、HEAD、OPTIONS） | 无 | 30 分钟 |
| L2 | 非安全方法（POST、PUT 等） | 点击确认 | 15 分钟 |
| L3 | 上游传入 `X-PC-Risk: high` | 等待时间更长 | 5 分钟 |

级别可通过 `challenge.level` 固定，`auto` 时按上表推断。
`X-PC-Risk` 只能提升级别，不能降低，因此客户端伪造该头无收益。

通行证有效期按级别分别配置于 `clearance.ttl_by_level`。

## 快速开始

环境要求：Python 3.11 及以上（依赖标准库 `tomllib`）。

```bash
pip install -r requirements.txt

# 生成密钥
python -c "import secrets; print(secrets.token_hex(32))"

# 注入密钥（Linux / macOS）
export PC_SECRET=<上一步输出>
# Windows: $env:PC_SECRET = "<上一步输出>"

python app.py
curl -s http://127.0.0.1:8090/__pc/healthz
```

配置文件为 `customs.toml`。所有站点默认 `enabled = false`，需显式开启。
配置变更由 mtime 轮询自动加载，无需重启；加载失败时保留上一份有效配置。

不部署 Nginx 也可验证完整流程：

```bash
python demo.py        # http://127.0.0.1:8091/
```

该示例启动一个业务站点，通过 WSGI 中间件接入 PelaCustoms。

## Nginx 集成

最小可用配置：

```nginx
location = /__pc/auth {
    internal;
    proxy_pass http://127.0.0.1:8090/__pc/auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI    $request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_set_header X-Real-IP         $remote_addr;
}

location ^~ /__pc/ {
    proxy_pass http://127.0.0.1:8090;
    proxy_set_header Host             $host;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Request-ID     $request_id;
}

location / {
    auth_request /__pc/auth;
    error_page 401 =200 @pc_challenge;
    proxy_pass http://backend;
}

location @pc_challenge {
    proxy_pass http://127.0.0.1:8090/__pc/challenge;
    proxy_set_header X-PC-Original-URI $request_uri;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-Host  $host;
    proxy_set_header X-Real-IP         $remote_addr;
}
```

含日志格式、fail-open、多站点的完整配置见 [deploy/nginx.conf.sample](deploy/nginx.conf.sample)。

### 页面模式与 API 模式

被保护的对象不同，配置不可混用。

| 形态 | 适用场景 | 拒绝时返回 | 参考配置 |
| --- | --- | --- | --- |
| 页面模式 | 后台入口、登录页；攻击面就是页面本身 | `200` + 质询页 HTML | [deploy/nginx.conf.sample](deploy/nginx.conf.sample) |
| API 模式 | 单页应用、前后端分离；昂贵的是接口 | `401` + `X-PC-Challenge` 头 | [deploy/nginx.api-mode.conf](deploy/nginx.api-mode.conf) |

页面模式把 401 改写为 200（`error_page 401 =200 @pc_challenge`），浏览器按正常页面处理，监控也不会把质询计入错误率。**该改写不能用于接口**：`fetch` 会判定 `res.ok === true`，随后把质询页 HTML 当 JSON 解析失败，最终报出与真实原因无关的解析错误。

**页面模式不适用于单页应用。** 若页面只是一个 `index.html`，业务数据全部经由 `/api/*` 取得，则页面层的质询没有意义 —— 攻击者不会请求页面。此时应改用 API 模式，把保护点移到接口上。

API 模式下，`/__pc/auth` 的拒绝响应携带 `X-PC-Deny: 1`，`/api/` 用 `auth_request_set` 取出并透出为 `X-PC-Challenge`：

```nginx
auth_request_set $pc_deny $upstream_http_x_pc_deny;
add_header X-PC-Challenge $pc_deny always;
```

变量为空时 nginx 不发送该头，于是两种 401 得以区分：

| 来源 | 响应 | 前端处理 |
| --- | --- | --- |
| 判定拒绝 | `401` + `X-PC-Challenge: required` | 跳转质询页 |
| 后端自身 | `401`，无该头 | 按登录过期处理 |

**这个区分是必要的。** 若混为一谈，应用层 401 会被误认为需要验证，通过质询后重试仍然是 401，再次触发质询，形成死循环。

前端据此分流：

```js
if (res.status === 401 && res.headers.get('X-PC-Challenge')) {
  location.href = '/__pc/challenge?rd=' + encodeURIComponent(location.pathname);
}
```

集成时需注意三点：

**状态码约定。** `auth_request` 接受 2xx 为放行、401 与 403 为拒绝，其余状态码一律
转换为 500 返回客户端。`/__pc/auth` 仅返回这三种状态，拒绝原因通过 `X-PC-Reason`
响应头传递。

**路径隔离。** `/__pc/` 必须绕过 `auth_request`，否则判定子请求自身会被判定，
形成递归。

**请求体不传递。** 子请求不携带请求体，因此被拦截的 POST 请求在验证通过后无法
恢复其表单内容。307 重定向不能解决该问题：浏览器沿用请求体重发至质询页后，
页面渲染即消耗了请求体。推荐在提交前确认通行证状态：

```js
async function ensureClearance() {
  const res = await fetch('/__pc/auth', {
    headers: { 'X-Original-URI': location.pathname },
  });
  if (res.status === 200) return true;
  location.href = '/__pc/challenge?rd=' + encodeURIComponent(location.pathname);
  return false;
}

form.addEventListener('submit', async (event) => {
  if (!(await ensureClearance())) event.preventDefault();
});
```

## 配置参考

`[defaults]` 为基线，`[sites."域名"]` 仅覆盖需要变更的字段。
完整注释见 [customs.example.toml](customs.example.toml)。

### server

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `listen` | `127.0.0.1:8090` | 仅监听回环地址 |
| `public_origin` | 空 | 必须留空，见下文 |
| `fail_mode` | `closed` | 自身异常时 `open` 放行 / `closed` 拒绝 |
| `secret` | — | 建议通过环境变量 `PC_SECRET` 注入，长度不少于 16 位 |
| `reload_interval` | `5s` | 配置轮询间隔 |

### protect

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `paths` | `["/**"]` | 触发质询的路径 |
| `exclude` | `/static/**`、`/favicon.ico`、`/robots.txt`、`/healthz` | 排除路径，先于 `paths` 判定 |
| `methods` | 全部 | 受管方法 |

路径使用 glob：`*` 不跨越 `/`，`**` 跨越 `/`，`re:` 前缀表示正则。

### clearance

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `name` | `pc_clearance` | cookie 名称 |
| `domain` | 空 | 空为 host-only；多子域填 `.example.com` |
| `ttl` | `30m` | 支持 `30m` / `90s` / `2h`，纯数字按秒解析 |
| `ttl_by_level` | 30m / 15m / 5m | 按质询级别区分有效期 |
| `secure` | `true` | 生产环境必须为 true |
| `http_only` | `true` | 前端不需读取该 cookie |
| `same_site` | `Lax` | `Lax` / `Strict` / `None` |
| `bind_ip` | `false` | 绑定 IP 会误伤移动网络切换 |
| `bind_ua` | `true` | 绑定 User-Agent |

### challenge

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `level` | `auto` | `auto` / `1` / `2` / `3` |
| `page_ttl` | `90s` | 质询页有效期，与通行证有效期无关 |
| `difficulty` | `20000` | 期望哈希次数，换算为前导零位数（20000 → 4 位） |
| `risk_header` | `X-PC-Risk` | 上游用于提升级别的请求头 |
| `click_gate` | `true` | L2 起是否要求点击关卡 |
| `automation_threshold` | `6` | 环境异常特征累加至该分值后拒绝 |
| `track_strict` | `false` | 轨迹评分超过阈值时是否直接拒绝 |
| `track_threshold` | `4` | 轨迹评分拒绝阈值 |
| `strict_level3` | `true` | L3 提高难度并启用严格轨迹判定 |

### crawlers / brand

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `allow_verified` | `true` | 放行搜索引擎，否则全屏质询会阻止收录 |
| `ua_list` | Googlebot、bingbot、Baiduspider 等 | 直接放行的 User-Agent 关键字 |
| `name` | `PELAGIC BEACON` | 质询页品牌文字 |
| `logo` | `/__pc/static/mark.svg` | 品牌图标路径 |
| `theme` | `dark` | `dark` / `light` / `auto` |
| `attribution` | `true` | 是否显示品牌与页脚链接 |

### 环境变量

| 变量 | 说明 |
| --- | --- |
| `PC_SECRET` | 签名密钥，长度不少于 16 位；存在时覆盖配置文件中的 `server.secret` |
| `PC_CONFIG` | 配置文件路径，默认 `./customs.toml` |
| `PC_STRICT_CONFIG` | 设为 `1` 时，配置自检未通过则拒绝启动 |
| `PC_LISTEN` | `app.py` 启动时的监听地址，覆盖配置文件 |
| `PC_LOG_LEVEL` | 日志级别，默认 `INFO` |
| `PC_DEBUG` | 设为 `1` 时启用 Flask 调试模式 |

### 托管模式

将质询页部署在独立域名（如 `customs.example.com`）的方案不受支持。
通行证是站点域下的 cookie，若质询页位于另一域名，该 cookie 无法被业务域读取，
验证通过后请求仍会被拦截。

如需跨域方案，需要在业务侧接受质询后携带的令牌，属于另一套集成方式。
设置 `public_origin` 会在启动时直接报错，不会静默降级。

## 运维

```bash
curl -s http://127.0.0.1:8090/__pc/healthz
```

返回 `configured`、`degraded`、`warnings`、`last` 四个字段。
`warnings` 非空表示存在危险配置组合，例如监听非回环地址或密钥缺失。
启动与热载时都会执行自检；需要将其转为硬失败时设置 `PC_STRICT_CONFIG=1`。

判定结果记录在 `X-PC-Reason` 响应头：

| 值 | 含义 |
| --- | --- |
| `excluded` | 命中排除路径 |
| `crawler` | 命中爬虫白名单 |
| `cleared` | 通行证有效 |
| `challenge` | 返回 401，需要质询 |
| `bad_ip` / `bad_ua` | 通行证绑定的特征已变更 |
| `unconfigured` | 未配置密钥 |

`/__pc/verify` 的失败原因：`wrong`、`expired`、`invalid`、`automation`、`interaction`。

**通行证撤销。** 没有单张撤销接口。更换 `PC_SECRET` 并重启会使全部在途通行证同时失效，
全站用户需要重新验证一次。这是无状态签名的直接代价。

**进程数量。** 必须为单进程。状态保存在内存，多 worker 各自独立记录限流数据。

## 部署

```bash
git clone <repo> /opt/pelacustoms
cd /opt/pelacustoms
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp customs.example.toml customs.toml
```

随后修改 `customs.toml`：开启目标站点（`enabled = true`）、设置 `sitekey`、
确认 `clearance.secure = true`。

### systemd

```ini
[Unit]
Description=PelaCustoms
After=network.target

[Service]
Type=simple
User=pc
WorkingDirectory=/opt/pelacustoms
Environment=PC_SECRET=replace-me
Environment=PC_CONFIG=/opt/pelacustoms/customs.toml
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/opt/pelacustoms/.venv/bin/gunicorn -w 1 -b 127.0.0.1:8090 "app:app"
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/pelacustoms

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now pelacustoms
```

`-w 1` 为必需配置，原因见上文「进程数量」。

Windows 环境：

```powershell
$env:PC_SECRET = "replace-me"
waitress-serve --listen=127.0.0.1:8090 app:app
```

需要开机自启时使用 nssm 或计划任务注册为服务。

### Nginx

复制 [deploy/nginx.conf.sample](deploy/nginx.conf.sample)，修改 `upstream` 与 `server_name`。

```bash
nginx -t && systemctl reload nginx
```

### 验证

```bash
# 服务状态与配置自检
curl -s http://127.0.0.1:8090/__pc/healthz

# 未携带通行证，预期 401
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'X-Original-URI: /' -H 'X-Original-Method: GET' \
  http://127.0.0.1:8090/__pc/auth

# 排除路径，预期 200
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'X-Original-URI: /favicon.ico' -H 'X-Original-Method: GET' \
  http://127.0.0.1:8090/__pc/auth
```

预期结果：`configured: true`、`warnings: []`、401、200。

随后在浏览器中走完整流程：出现质询页、完成验证、返回原页面、刷新后不再拦截。

**故障行为需实测。** 停止 PelaCustoms 后访问站点，Nginx 返回 500 还是放行，
取决于 Nginx 版本与 `error_page` 配置。若需要 fail-open，按
[deploy/nginx.conf.sample](deploy/nginx.conf.sample) 末尾的说明配置，并在配置后重新测试。

### 升级

```bash
cd /opt/pelacustoms
git pull
. .venv/bin/activate && pip install -r requirements.txt
systemctl restart pelacustoms
```

配置变更无需重启；更换密钥需要重启。

## 限制

- 爬虫白名单仅匹配 User-Agent，可被伪造。需要更严格策略时关闭 `allow_verified`。
- 状态保存在进程内存，仅支持单实例单进程部署。多实例需替换 `store.py` 实现。
- 可拦截零成本自动化请求。无法防御真实浏览器配合代理池或人工代答的定向攻击，
  该层防护应由业务侧限流与账号策略承担。
- fail-open 的实现依赖 Nginx 版本，无法在文档中给出统一结论。

## 目录结构

```
app.py                    生产入口
demo.py                   示例业务站 + WSGI 中间件
customs.toml              当前配置
customs.example.toml      带注释的配置示例
pelacustoms/
  config.py               TOML 加载、校验、热载
  matcher.py              URI 归一化与路径匹配
  clearance.py            通行证签发与校验
  core.py                 判定、分级、PoW、评分
  routes.py               /__pc/* 接口与 auth_request 契约
  middleware.py           WSGI 中间件
  store.py                限流与最近结果
static/pc/                样式、脚本、PoW worker、品牌图标
templates/challenge.html  质询页
deploy/nginx.conf.sample  Nginx 配置
deploy/preview.html       质询页样式预览
tests/test_flow.py        自检
tests/smoke_http.py       HTTP 冒烟测试（需先运行 demo.py）
```

```bash
python tests/test_flow.py
```

## 许可

代码采用 MIT 许可。品牌名称与标识不随代码授权，规则见 [TRADEMARK.md](TRADEMARK.md)；
免责声明与使用限制见 [DISCLAIMER.md](DISCLAIMER.md)。
