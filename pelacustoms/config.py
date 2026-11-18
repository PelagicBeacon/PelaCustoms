"""PelaCustoms 配置：TOML 加载、校验、热载。

三条硬规矩（见 README「配置」一节）：
1. 配置写错不能把站打挂 —— 校验失败保留上一份可用配置，只在日志和 /healthz 里报 degraded。
2. 判定路径上绝不碰磁盘 —— 配置一次性编进内存，重载靠后台线程 stat 轮询 / SIGHUP。
3. 默认不启用 —— 没显式打开 [sites] 时一律放行，免得刚接入就被全站质询。
"""
from __future__ import annotations

import copy
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

try:
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    try:
        import tomli as _toml  # type: ignore
    except ModuleNotFoundError:
        _toml = None

log = logging.getLogger("pelacustoms.config")

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


class ConfigError(Exception):
    """配置非法。加载时抛出，调用方保留上一份可用配置。"""


# ============================================================
# 时长
# ============================================================
_DUR_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?$", re.I)
_DUR_UNIT = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0, "": 1.0}


def parse_duration(value: Any, where: str) -> float:
    """'30m' / '90s' / '2h' / 1800 → 秒（float）。

    不接受裸数字以外的隐式单位：写 30 就是 30 秒，不是 30 分钟。
    """
    if isinstance(value, bool):
        raise ConfigError(f"{where}: 期望时长，得到布尔值")
    if isinstance(value, (int, float)):
        if value < 0:
            raise ConfigError(f"{where}: 时长不能为负")
        return float(value)
    if not isinstance(value, str):
        raise ConfigError(f"{where}: 期望时长字符串（30m / 90s / 2h），得到 {type(value).__name__}")
    m = _DUR_RE.match(value)
    if not m:
        raise ConfigError(f"{where}: 无法解析时长 {value!r}（例：30m / 90s / 2h）")
    return float(m.group(1)) * _DUR_UNIT[(m.group(2) or "").lower()]


# ============================================================
# 取值辅助：类型不对就报错，绝不静默吞掉
# ============================================================
def _check_keys(data: dict, allowed: set[str], where: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigError(f"{where}: 未知字段 {unknown}（拼写错误？可用：{sorted(allowed)}）")


def _str(data: dict, key: str, default: str, where: str) -> str:
    v = data.get(key, default)
    if not isinstance(v, str):
        raise ConfigError(f"{where}.{key}: 期望字符串")
    return v


def _bool(data: dict, key: str, default: bool, where: str) -> bool:
    v = data.get(key, default)
    if not isinstance(v, bool):
        raise ConfigError(f"{where}.{key}: 期望 true / false")
    return v


def _int(data: dict, key: str, default: int, where: str, lo: int | None = None,
         hi: int | None = None) -> int:
    v = data.get(key, default)
    if isinstance(v, bool) or not isinstance(v, int):
        raise ConfigError(f"{where}.{key}: 期望整数")
    if lo is not None and v < lo:
        raise ConfigError(f"{where}.{key}: 不能小于 {lo}")
    if hi is not None and v > hi:
        raise ConfigError(f"{where}.{key}: 不能大于 {hi}")
    return v


def _dur(data: dict, key: str, default: float, where: str) -> float:
    if key not in data:
        return float(default)
    return parse_duration(data[key], f"{where}.{key}")


def _patterns(data: dict, key: str, default: list[str], where: str) -> list[str]:
    v = data.get(key, default)
    if not isinstance(v, list) or not all(isinstance(i, str) for i in v):
        raise ConfigError(f"{where}.{key}: 期望字符串数组")
    for pat in v:
        if pat.startswith("re:"):
            try:
                re.compile(pat[3:])
            except re.error as exc:
                raise ConfigError(f"{where}.{key}: 正则写错 {pat!r}（{exc}）") from exc
    return list(v)


def _methods(data: dict, key: str, default: list[str], where: str) -> list[str]:
    v = _patterns(data, key, default, where)
    return [m.upper() for m in v]


def _level_map(data: dict, key: str, default: dict[str, float], where: str) -> dict[int, float]:
    raw = data.get(key, default)
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}.{key}: 期望映射，键是 1 / 2 / 3，值写成 30m")
    out: dict[int, float] = {}
    for k, v in raw.items():
        try:
            lvl = int(k)
        except (TypeError, ValueError):
            raise ConfigError(f"{where}.{key}: 键必须是 1 / 2 / 3，得到 {k!r}") from None
        if lvl not in (1, 2, 3):
            raise ConfigError(f"{where}.{key}: 只支持 1 / 2 / 3 档")
        out[lvl] = parse_duration(v, f"{where}.{key}.{k}")
    return out


# ============================================================
# 各配置段
# ============================================================
@dataclass
class ProtectCfg:
    """触发范围。paths / exclude 用 glob（** 跨目录，* 不跨），re: 前缀走正则。"""

    paths: list[str] = field(default_factory=lambda: ["/**"])
    exclude: list[str] = field(default_factory=lambda: [
        "/static/**", "/favicon.ico", "/robots.txt", "/healthz",
    ])
    methods: list[str] = field(default_factory=lambda: list(
        ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")))

    KEYS = {"paths", "exclude", "methods"}
    WHERE = "protect"

    def apply(self, data: dict, where: str) -> None:
        _check_keys(data, self.KEYS, where)
        w = f"{where}.{self.WHERE}" if where else self.WHERE
        self.paths = _patterns(data, "paths", self.paths, w)
        self.exclude = _patterns(data, "exclude", self.exclude, w)
        self.methods = _methods(data, "methods", self.methods, w)
        if not self.paths:
            raise ConfigError(f"{w}.paths: 不能为空（想全放行请把站点 enabled 设为 false）")


@dataclass
class ClearanceCfg:
    """通行证（clearance cookie）。"""

    enabled: bool = True
    name: str = "pc_clearance"
    domain: str = ""          # 空 = host-only；多子域填 ".example.com"
    path: str = "/"
    secure: bool = True
    http_only: bool = True    # 同源代理下前端不需要读它
    same_site: str = "Lax"
    ttl: float = 1800.0
    ttl_by_level: dict[int, float] = field(default_factory=lambda: {1: 1800.0, 2: 900.0, 3: 300.0})
    bind_ip: bool = False     # 默认不绑：移动网络切换很常见（Reeflet 上踩过）
    bind_ua: bool = True

    KEYS = {"enabled", "name", "domain", "path", "secure", "http_only",
            "same_site", "ttl", "ttl_by_level", "bind_ip", "bind_ua"}
    WHERE = "clearance"

    def apply(self, data: dict, where: str) -> None:
        _check_keys(data, self.KEYS, where)
        w = f"{where}.{self.WHERE}" if where else self.WHERE
        self.enabled = _bool(data, "enabled", self.enabled, w)
        self.name = _str(data, "name", self.name, w)
        self.domain = _str(data, "domain", self.domain, w)
        self.path = _str(data, "path", self.path, w)
        self.secure = _bool(data, "secure", self.secure, w)
        self.http_only = _bool(data, "http_only", self.http_only, w)
        self.same_site = _str(data, "same_site", self.same_site, w)
        if self.same_site not in ("Lax", "Strict", "None"):
            raise ConfigError(f"{w}.same_site: 只能是 Lax / Strict / None")
        self.ttl = _dur(data, "ttl", self.ttl, w)
        self.ttl_by_level = _level_map(data, "ttl_by_level", self.ttl_by_level, w)
        self.bind_ip = _bool(data, "bind_ip", self.bind_ip, w)
        self.bind_ua = _bool(data, "bind_ua", self.bind_ua, w)
        if not self.name or any(c in self.name for c in " \t;,"):
            raise ConfigError(f"{w}.name: cookie 名不能含空白或分隔符")
        if self.ttl <= 0:
            raise ConfigError(f"{w}.ttl: 必须大于 0")

    def ttl_for(self, level: int) -> float:
        return float(self.ttl_by_level.get(level, self.ttl))


@dataclass
class ChallengeCfg:
    """质询本身的参数。"""

    level: str = "auto"        # auto / "1" / "2" / "3"
    page_ttl: float = 90.0     # 质询页存活时间，不是 clearance 寿命
    difficulty: int = 20000    # 期望哈希次数 → 前导 0 位数
    risk_header: str = "X-PC-Risk"
    click_gate: bool = True    # L2 起是否要求点击关卡
    automation_threshold: int = 6
    track_strict: bool = False
    track_threshold: int = 4
    strict_level3: bool = True  # L3 是否强制最高难度 + 严格轨迹

    KEYS = {"level", "page_ttl", "difficulty", "risk_header", "click_gate",
            "automation_threshold", "track_strict", "track_threshold", "strict_level3"}
    WHERE = "challenge"

    def apply(self, data: dict, where: str) -> None:
        _check_keys(data, self.KEYS, where)
        w = f"{where}.{self.WHERE}" if where else self.WHERE
        lvl = data.get("level", self.level)
        if isinstance(lvl, int) and not isinstance(lvl, bool):
            lvl = str(lvl)
        if lvl not in ("auto", "1", "2", "3"):
            raise ConfigError(f"{w}.level: 只能是 auto / 1 / 2 / 3")
        self.level = lvl
        self.page_ttl = _dur(data, "page_ttl", self.page_ttl, w)
        self.difficulty = _int(data, "difficulty", self.difficulty, w, lo=1)
        self.risk_header = _str(data, "risk_header", self.risk_header, w)
        self.click_gate = _bool(data, "click_gate", self.click_gate, w)
        self.automation_threshold = _int(data, "automation_threshold",
                                         self.automation_threshold, w, lo=1)
        self.track_strict = _bool(data, "track_strict", self.track_strict, w)
        self.track_threshold = _int(data, "track_threshold", self.track_threshold, w, lo=1)
        self.strict_level3 = _bool(data, "strict_level3", self.strict_level3, w)
        if self.page_ttl <= 0:
            raise ConfigError(f"{w}.page_ttl: 必须大于 0")

    @property
    def prefix(self) -> int:
        """把「期望哈希次数」换算成前导 0 的十六进制位数（向上取整，3..6）。"""
        n = 1
        while n < 6 and (16 ** n) < max(1, self.difficulty):
            n += 1
        return max(3, min(n, 6))

    def prefix_for(self, level: int) -> int:
        base = self.prefix
        if self.strict_level3 and level >= 3:
            base += 1
        return max(3, min(base, 6))


@dataclass
class CrawlerCfg:
    allow_verified: bool = True
    ua_list: list[str] = field(default_factory=lambda: [
        "Googlebot", "bingbot", "Baiduspider", "YandexBot", "DuckDuckBot",
    ])
    # 说明：这里只按 UA 判断，UA 可伪造。要做真爬虫校验得反查 IP 归属，
    # 那会在判定路径上发起 DNS 查询 —— 宁可先不做，也不给判定点塞阻塞调用。
    # 需要更严就把 allow_verified 关掉。

    KEYS = {"allow_verified", "ua_list"}
    WHERE = "crawlers"

    def apply(self, data: dict, where: str) -> None:
        _check_keys(data, self.KEYS, where)
        w = f"{where}.{self.WHERE}" if where else self.WHERE
        self.allow_verified = _bool(data, "allow_verified", self.allow_verified, w)
        self.ua_list = _patterns(data, "ua_list", self.ua_list, w)


@dataclass
class BrandCfg:
    name: str = "PELAGIC BEACON"
    logo: str = "/__pc/static/mark.svg"
    theme: str = "dark"        # dark / light / auto
    attribution: bool = True
    license_url: str = "https://github.com/PelagicBeacon/PelaCustoms/blob/main/LICENSE"
    about_url: str = "https://github.com/orgs/PelagicBeacon/repositories"
    title: str = "正在检查你的浏览器"

    KEYS = {"name", "logo", "theme", "attribution", "license_url", "about_url",
            "title"}
    WHERE = "brand"

    def apply(self, data: dict, where: str) -> None:
        _check_keys(data, self.KEYS, where)
        w = f"{where}.{self.WHERE}" if where else self.WHERE
        self.name = _str(data, "name", self.name, w)
        self.logo = _str(data, "logo", self.logo, w)
        self.theme = _str(data, "theme", self.theme, w)
        if self.theme not in ("dark", "light", "auto"):
            raise ConfigError(f"{w}.theme: 只能是 dark / light / auto")
        self.attribution = _bool(data, "attribution", self.attribution, w)
        self.license_url = _str(data, "license_url", self.license_url, w)
        self.about_url = _str(data, "about_url", self.about_url, w)
        self.title = _str(data, "title", self.title, w)


@dataclass
class SiteCfg:
    """一个站点的完整策略。sites.X 里的字段只覆盖写到的那些。"""

    host: str = "*"
    sitekey: str = "default"
    enabled: bool = False
    protect: ProtectCfg = field(default_factory=ProtectCfg)
    clearance: ClearanceCfg = field(default_factory=ClearanceCfg)
    challenge: ChallengeCfg = field(default_factory=ChallengeCfg)
    crawlers: CrawlerCfg = field(default_factory=CrawlerCfg)
    brand: BrandCfg = field(default_factory=BrandCfg)

    HEAD_KEYS = {"sitekey", "enabled"}
    SECTIONS = ("protect", "clearance", "challenge", "crawlers", "brand")

    def clone(self) -> "SiteCfg":
        return copy.deepcopy(self)

    def apply(self, data: dict, where: str = "") -> None:
        w = where or self.host
        _check_keys(data, self.HEAD_KEYS | set(self.SECTIONS), w)
        self.sitekey = _str(data, "sitekey", self.sitekey, w)
        self.enabled = _bool(data, "enabled", self.enabled, w)
        for name in self.SECTIONS:
            raw = data.get(name)
            if raw is None:
                continue
            if not isinstance(raw, dict):
                raise ConfigError(f"{w}.{name}: 期望表（[.. .{name}]）")
            getattr(self, name).apply(raw, w)


@dataclass
class ServerCfg:
    listen: str = "127.0.0.1:8090"
    public_origin: str = ""     # 必须留空：托管模式尚未实现，设了会拒绝启动
    fail_mode: str = "closed"   # 自身异常：open 放行 / closed 拒绝
    secret: str = ""            # 优先 PC_SECRET 环境变量
    secret_min_len: int = 16
    reload_interval: float = 5.0
    cookie_secure_default: bool = True

    KEYS = {"listen", "public_origin", "fail_mode", "secret", "secret_min_len",
            "reload_interval", "cookie_secure_default"}
    WHERE = "server"

    def apply(self, data: dict) -> None:
        w = self.WHERE
        _check_keys(data, self.KEYS, w)
        self.listen = _str(data, "listen", self.listen, w)
        self.public_origin = _str(data, "public_origin", self.public_origin, w).rstrip("/")
        self.fail_mode = _str(data, "fail_mode", self.fail_mode, w)
        if self.fail_mode not in ("open", "closed"):
            raise ConfigError(f"{w}.fail_mode: 只能是 open / closed")
        self.secret = _str(data, "secret", self.secret, w)
        self.secret_min_len = _int(data, "secret_min_len", self.secret_min_len, w, lo=8)
        self.reload_interval = _dur(data, "reload_interval", self.reload_interval, w)
        self.cookie_secure_default = _bool(data, "cookie_secure_default",
                                           self.cookie_secure_default, w)
        if self.public_origin:
            # 不是懒得做，是这条路在 cookie 上走不通：
            # 质询页若挂在另一个域名下，签发的通行证会落在那个域名上，
            # 业务站点的 auth_request 根本读不到它。要跨域就得改成一串跳转 +
            # 业务侧认查询参数，那是另一套东西，不该用一个开关假装能开。
            raise ConfigError(
                w + ".public_origin: 托管模式尚未实现，请留空走代理模式。"
                "\n    原因：质询页挂在独立域名时，通行证 cookie 会落在那个域名上，"
                "业务站点读不到；跨域方案需要业务侧额外改造，不是一个配置项能打开的。")

    @property
    def configured(self) -> bool:
        return len(self.secret) >= self.secret_min_len

    @property
    def proxy_mode(self) -> bool:
        return not self.public_origin


@dataclass
class Config:
    server: ServerCfg = field(default_factory=ServerCfg)
    sites: dict[str, SiteCfg] = field(default_factory=dict)
    source: str = ""
    loaded_at: float = 0.0
    #: 配置自检发现的危险组合。不阻止启动（除非 PC_STRICT_CONFIG=1），
    #: 但会写进日志并在 /__pc/healthz 里露出来。
    warnings: list[str] = field(default_factory=list)

    # ---------------------------------------------------------- 查找
    def for_host(self, host: str) -> SiteCfg | None:
        """按 Host 找站点：精确匹配 → '*' 兜底 → 只有一个站点时用它 → None（不管）。"""
        h = (host or "").strip().lower()
        if h.startswith("["):                    # [::1]:8080
            h = h.split("]")[0].lstrip("[")
        elif h.count(":") == 1:
            h = h.split(":")[0]
        if h in self.sites:
            return self.sites[h]
        if "*" in self.sites:
            return self.sites["*"]
        if len(self.sites) == 1:
            return next(iter(self.sites.values()))
        return None


# ============================================================
# 加载
# ============================================================
def _coerce(payload: dict) -> Config:
    if not isinstance(payload, dict):
        raise ConfigError("顶层必须是表")
    top_keys = set(payload)
    allowed = {"server", "defaults", "sites"}
    unknown = sorted(top_keys - allowed)
    if unknown:
        raise ConfigError(f"顶层未知字段 {unknown}（可用：server / defaults / sites）")

    cfg = Config()
    if "server" in payload:
        cfg.server.apply(payload["server"])

    defaults = SiteCfg()
    base = payload.get("defaults") or {}
    if not isinstance(base, dict):
        raise ConfigError("defaults: 期望表")
    defaults.apply(base, where="defaults")

    raw_sites = payload.get("sites") or {}
    if not isinstance(raw_sites, dict):
        raise ConfigError("sites: 期望表，如 [sites.\"example.com\"]")
    for host, data in raw_sites.items():
        if not isinstance(data, dict):
            raise ConfigError(f"sites.{host}: 期望表")
        site = defaults.clone()
        site.host = str(host)
        site.apply(data, where=f"sites.{host}")
        cfg.sites[str(host).lower()] = site

    # 环境变量永远优先（生产用进程管理器注入，不用把密钥写进配置文件）
    env_secret = (os.getenv("PC_SECRET") or "").strip()
    if env_secret:
        cfg.server.secret = env_secret
    elif cfg.server.secret:
        log.warning("server.secret 写在配置文件里不安全，建议改用 PC_SECRET 环境变量")

    if not cfg.server.configured:
        log.warning("未配置 PC_SECRET（或短于 %d 位），将拒绝签发通行证",
                    cfg.server.secret_min_len)

    cfg.warnings = _audit(cfg)
    for w in cfg.warnings:
        log.warning("配置自检：%s", w)
    if cfg.warnings and os.getenv("PC_STRICT_CONFIG", "").strip().lower() in (
            "1", "true", "yes", "on"):
        raise ConfigError(
            "配置自检未通过（PC_STRICT_CONFIG=1）：\n  - "
            + "\n  - ".join(cfg.warnings))

    keys = [s.sitekey for s in cfg.sites.values()]
    dup = sorted({k for k in keys if keys.count(k) > 1})
    if dup:
        raise ConfigError(f"sites: sitekey 重复 {dup}（每个站点必须唯一）")

    return cfg


_LOOPBACK = {"127.0.0.1", "localhost", "::1", ""}


def _listen_host(listen: str) -> str:
    text = (listen or "").strip()
    if text.startswith("["):                      # [::1]:8090
        return text[1:text.find("]")] if "]" in text else text
    if ":" in text:
        return text.rsplit(":", 1)[0]
    return text


def _audit(cfg: Config) -> list[str]:
    """配置自检：只针对那些「一个人记不住就会出事」的组合。

    这里**不**试图替人判断对错 —— 只把危险的搭配指出来。默认写日志 + 在
    /__pc/healthz 里露出来；想让它变成硬失败就设 PC_STRICT_CONFIG=1。
    """
    warns: list[str] = []

    host = _listen_host(cfg.server.listen)
    if host not in _LOOPBACK:
        warns.append(
            'server.listen = "' + cfg.server.listen + '" 不是回环地址。'
            "PelaCustoms 设计上只该被站点自己的 nginx 反向代理，"
            "直接对公网监听等于把判定点交出去（也更可能被人蹭）。")

    if not cfg.server.configured:
        warns.append("没有可用的 PC_SECRET（≥"
                     + str(cfg.server.secret_min_len) + " 位），将拒绝签发通行证。")

    return warns


def load_config(path: str) -> Config:
    """读并校验一个 TOML 文件。任何问题都抛 ConfigError。"""
    if _toml is None:
        raise ConfigError("未找到 tomllib / tomli，PelaCustoms 需要 Python >= 3.11")
    if not os.path.isfile(path):
        raise ConfigError(
            "配置文件不存在：" + path + "\n"
            "    照 customs.example.toml 抄一份就行：\n"
            "    Copy-Item customs.example.toml customs.toml   （Windows）\n"
            "    cp customs.example.toml customs.toml          （Linux/macOS）")
    with open(path, "rb") as fh:
        try:
            payload = _toml.load(fh)
        except Exception as exc:
            raise ConfigError(f"TOML 解析失败：{exc}") from exc
    cfg = _coerce(payload)
    cfg.source = path
    cfg.loaded_at = time.time()
    return cfg


class ConfigStore:
    """在内存里持有当前可用配置，后台线程按 mtime 热载。

    关键约定：重载失败**不**替换当前配置，只记日志并把健康状态标成 degraded。
    """

    def __init__(self, path: str, interval: float = 5.0):
        self.path = path
        self.interval = max(0.5, interval)
        self._lock = threading.RLock()
        self._cfg = load_config(path)      # 首次加载失败直接抛，让进程起不来
        self._mtime = self._stat_mtime()
        self._error: str = ""
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ---------------------------------------------------------- 读
    def get(self) -> Config:
        with self._lock:
            return self._cfg

    @property
    def last_error(self) -> str:
        return self._error

    def _stat_mtime(self) -> float:
        try:
            return os.stat(self.path).st_mtime
        except OSError:
            return 0.0

    # ---------------------------------------------------------- 重载
    def reload(self) -> bool:
        """手动重载。成功返回 True；失败保留旧配置并返回 False。"""
        with self._lock:
            mtime = self._stat_mtime()
            try:
                cfg = load_config(self.path)
            except ConfigError as exc:
                self._error = str(exc)
                log.error("配置重载失败，继续使用上一份：%s", exc)
                return False
            except Exception as exc:                     # noqa: BLE001 - 兜底
                self._error = f"重载异常：{exc}"
                log.exception("配置重载异常，继续使用上一份")
                return False
            self._cfg = cfg
            self._mtime = mtime
            self._error = ""
            log.info("配置已重载：%s（%d 个站点）", self.path, len(cfg.sites))
            return True

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                mtime = self._stat_mtime()
                if mtime and mtime != self._mtime:
                    self.reload()
            except Exception:                            # noqa: BLE001
                log.exception("配置轮询异常")

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="pc-config-reload",
                                            daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
