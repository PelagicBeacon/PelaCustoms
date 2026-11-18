"""PelaCustoms 核心：准入判定、质询签发、验证、通行证发放。

和 PelaReeflet 的关系：验证内核（环境探测评分、轨迹评分、PoW 校验）沿用
Reeflet 的那一套，因为那些阈值是在真实流量上交过学费的。Customs 多出来的是
外面一层：**判定点**（auth_request 子请求）、**分级**、**通行证**。

三条设计原则
------------
1. 判定无状态：通行证是签名过的 JSON，快路径不查任何共享存储。
2. 先验答案再记账：算错了 PoW 不会把质询票烧掉，用户能重试。
3. 只拒绝确定性异常：行为分析拿不准的一律放行，后面还有 PoW 兜底。
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field

from . import clearance
from .config import Config, SiteCfg, SAFE_METHODS
from .matcher import PatternSet, is_protected, normalize_path

MAX_NONCE = 10 ** 15

#: 命中即拒绝的确定性信号（一条就够）。
#: chrome_missing 刻意不在这里：window.chrome 在页面里可伪造，挡住不认真的
#: 自动化没有价值，却会误伤国产手机壳浏览器 —— 详见 Reeflet 的同类注释。
HARD_AUTOMATION = frozenset({"webdriver", "headless_ua"})

MOBILE_UA_HINTS = (
    "mobile", "android", "iphone", "ipad", "ipod", "harmonyos", "windows phone",
    "micromessenger", "opera mini", "kindle", "silk/", "blackberry", "webview",
)


# ============================================================
# 对外结果
# ============================================================
@dataclass
class Decision:
    """一次准入判定的结论。status 是给 nginx 看的那个码。"""

    allow: bool
    status: int = 200          # 200 放行 / 401 需质询 / 403 硬拒绝
    reason: str = "ok"
    level: int = 0
    path: str = ""
    sitekey: str = ""

    def headers(self) -> dict:
        h = {"Cache-Control": "no-store", "X-PC-Reason": self.reason}
        if self.status != 200:
            # 只在拒绝时出现。API 模式靠它区分「判定子请求拒绝」与「后端自己返回
            # 的 401」：少了这个区分，应用层的登录过期会被误认成需要质询，
            # 前端就会陷入「质询 → 重试 → 仍是 401 → 再次质询」的死循环。
            h["X-PC-Deny"] = "1"
        if self.level:
            h["X-PC-Level"] = str(self.level)
        if self.sitekey:
            h["X-PC-Site"] = self.sitekey
        return h


@dataclass
class PageData:
    """渲染质询页所需的一切（不含任何秘密）。"""

    pend: str
    challenge: str
    prefix: int
    level: int
    path: str
    sitekey: str
    method: str
    origin: str = ""            # 资源前缀；代理模式下为空（相对路径）
    redirect_url: str = ""
    brand: dict = field(default_factory=dict)
    click_gate: bool = False


# ============================================================
# 打分（沿用 Reeflet 的判据）
# ============================================================
def _looks_mobile(ua: str, features: dict) -> bool:
    text = (ua or "").lower()
    if any(hint in text for hint in MOBILE_UA_HINTS):
        return True
    if features.get("mobile") is True:
        return True
    try:
        return int(features.get("touch") or 0) == 1 and not text
    except (TypeError, ValueError):
        return False


def score_features(features: dict) -> tuple[int, list[str]]:
    """无头 / 自动化环境评分。字段缺失 = 未知 = 不计分。"""
    score = 0
    reasons: list[str] = []

    def as_int(key):
        if key not in features:
            return None
        try:
            return int(features.get(key) or 0)
        except (TypeError, ValueError):
            return None

    ua = str(features.get("ua") or "")
    if features.get("webdriver") is True:
        reasons.append("webdriver")
    if features.get("headless_ua") is True or "headlesschrome" in ua.lower():
        reasons.append("headless_ua")

    if "chrome/" in ua.lower() and features.get("chrome") is False:
        reasons.append("chrome_missing")
        score += 1 if _looks_mobile(ua, features) else 3

    plugins = as_int("plugins")
    languages = as_int("languages")
    hardware = as_int("hardware")
    depth = as_int("depth")
    screen_w = as_int("screen_w")

    if plugins == 0 and languages == 0:
        reasons.append("empty_env")
        score += 3
    if hardware == 0:
        reasons.append("no_hardware")
        score += 2
    if depth == 0:
        reasons.append("no_color_depth")
        score += 2
    if screen_w is not None and screen_w <= 0:
        reasons.append("no_screen")
        score += 2

    return score, reasons


def norm_path_points(raw) -> list[tuple[float, float, float]]:
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw[-200:]:
        if isinstance(item, (list, tuple)) and len(item) >= 3:
            try:
                out.append((float(item[0]), float(item[1]), float(item[2])))
            except (TypeError, ValueError):
                continue
        elif isinstance(item, dict):
            try:
                out.append((float(item.get("x")), float(item.get("y")),
                            float(item.get("t"))))
            except (TypeError, ValueError):
                continue
    return out


def track_metrics(points: list[tuple[float, float, float]]) -> dict:
    """鼠标轨迹评分（0~6）。

    故意不用时间间隔 dt 判机器人：组件把 mousemove 节流到 25ms，真人采到的
    dt 本来就高度整齐，用它必然误伤。这里只做评分，strict 模式才拒绝。
    """
    n = len(points)
    if n < 2:
        return {"score": 0, "n": n, "dx_unique": 0, "y_range": 0.0,
                "back_ratio": 0.0, "length": 0.0}

    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    xs_nz = [xs[i + 1] - xs[i] for i in range(n - 1)]
    dxs = [d for d in xs_nz if abs(d) > 0.5]
    y_range = max(ys) - min(ys)
    back = sum(1 for d in xs_nz if d < -0.5)
    back_ratio = back / len(xs_nz) if xs_nz else 0.0

    length = 0.0
    for i in range(1, n):
        dx = xs[i] - xs[i - 1]
        dy = ys[i] - ys[i - 1]
        length += (dx * dx + dy * dy) ** 0.5

    score = 0
    if len(dxs) >= 8 and len({round(d, 1) for d in dxs}) <= 2:
        score += 2          # 位移值只有一两种 = 脚本线性插值
    if y_range < 0.5:
        score += 2          # 人手几乎画不出完美水平线
    if len(dxs) > 10 and back == 0:
        score += 1
    if n > 120 and length > 5000:
        score += 1
    return {"score": min(score, 6), "n": n,
            "dx_unique": len({round(d, 1) for d in dxs}),
            "y_range": round(y_range, 2), "back_ratio": round(back_ratio, 3),
            "length": round(length, 2)}


# ============================================================
# 引擎
# ============================================================
class Engine:
    def __init__(self, cfg: Config, state):
        self.cfg = cfg
        self.state = state        # MemoryStore：限流 + 最近一次结果（可选）
        self._cache: dict[str, tuple[float, PatternSet, PatternSet]] = {}
        self._cache_cfg_id: int = id(cfg)

    # ---------------------------------------------------------- 预编译
    def _patterns(self, site: SiteCfg) -> tuple[PatternSet, PatternSet]:
        """按站点缓存已编译的模式，配置换代时整体失效。"""
        if id(self.cfg) != self._cache_cfg_id:
            self._cache.clear()
            self._cache_cfg_id = id(self.cfg)
        hit = self._cache.get(site.sitekey)
        if hit is None:
            hit = (id(site.protect), PatternSet(site.protect.paths),
                   PatternSet(site.protect.exclude))
            self._cache[site.sitekey] = hit
        return hit[1], hit[2]

    def _key(self, site: SiteCfg) -> str:
        return clearance.derive_key(self.cfg.server.secret, site.sitekey)

    # ---------------------------------------------------------- 判定
    def decide(self, *, host: str, method: str, uri: str, cookie: str | None,
               ip: str | None, ua: str | None, risk: str = "") -> Decision:
        path = normalize_path(uri)

        if not self.cfg.server.configured:
            # 密钥没配：宁可不工作，也不能用弱密钥签票
            allow = self.cfg.server.fail_mode == "open"
            return Decision(allow=allow, status=200 if allow else 403,
                            reason="unconfigured", path=path)

        site = self.cfg.for_host(host)
        if site is None or not site.enabled:
            return Decision(allow=True, path=path)

        include, exclude = self._patterns(site)
        if not is_protected(path, include, exclude, method, site.protect.methods):
            return Decision(allow=True, reason="excluded", path=path,
                            sitekey=site.sitekey)

        if self._is_crawler(site, ua):
            return Decision(allow=True, reason="crawler", path=path,
                            sitekey=site.sitekey)

        if site.clearance.enabled:
            ok, reason, payload = clearance.verify(
                self._key(site), cookie or "", site.sitekey, ip, ua,
                site.clearance.bind_ip, site.clearance.bind_ua)
            if ok:
                return Decision(allow=True, reason="cleared", path=path,
                                sitekey=site.sitekey,
                                level=int(payload.get("lvl") or 0))

        level = self.pick_level(site, method, risk)
        return Decision(allow=False, status=401, reason="challenge", level=level,
                        path=path, sitekey=site.sitekey)

    def pick_level(self, site: SiteCfg, method: str, risk: str = "") -> int:
        """auto 规则：显式风险头 > 非安全方法 > 普通 GET。"""
        if site.challenge.level != "auto":
            return int(site.challenge.level)
        rv = (risk or "").strip().lower()
        if rv in ("high", "3"):
            return 3
        if rv in ("medium", "2"):
            return 2
        if method.upper() not in SAFE_METHODS:
            return 2
        return 1

    def _is_crawler(self, site: SiteCfg, ua: str | None) -> bool:
        if not site.crawlers.allow_verified or not ua:
            return False
        return any(token.lower() in ua.lower() for token in site.crawlers.ua_list
                   if token)

    # ---------------------------------------------------------- 签发质询页
    def issue_page(self, *, site: SiteCfg, path: str, method: str,
                   ip: str | None, ua: str | None, risk: str = "",
                   redirect_url: str = "") -> PageData:
        level = self.pick_level(site, method, risk)
        prefix = site.challenge.prefix_for(level)
        chal = secrets.token_hex(32)
        exp = int(time.time() + site.challenge.page_ttl)
        pend = clearance.pack(self._key(site), {
            "k": "pend",
            "sk": site.sitekey,
            "chal": chal,
            "pfx": prefix,
            "lvl": level,
            "p": path,
            "m": method.upper(),
            "ip": clearance.ip_fingerprint(ip),
            "ua": clearance.ua_fingerprint(ua),
            "exp": exp,
        })
        return PageData(
            pend=pend, challenge=chal, prefix=prefix, level=level, path=path,
            sitekey=site.sitekey, method=method.upper(),
            origin=self.cfg.server.public_origin, redirect_url=redirect_url,
            brand={
                "name": site.brand.name, "logo": site.brand.logo,
                "theme": site.brand.theme, "attribution": site.brand.attribution,
                "license": site.brand.license_url, "about": site.brand.about_url,
                "title": site.brand.title,
            },
            click_gate=site.challenge.click_gate and level >= 2,
        )

    # ---------------------------------------------------------- 验证并发证
    def verify(self, *, site: SiteCfg, body: dict, ip: str | None,
               ua: str | None) -> tuple[bool, str, str, float, int]:
        """返回 (ok, reason, cookie_value, ttl, level)。"""
        payload = clearance.unpack(self._key(site), str(body.get("pend") or ""))
        if not payload or payload.get("k") != "pend":
            return False, "invalid", "", 0, 0
        if str(payload.get("sk") or "") != site.sitekey:
            return False, "bad_sitekey", "", 0, 0
        if int(payload.get("exp") or 0) <= time.time():
            return False, "expired", "", 0, 0
        if not hmac.compare_digest(str(payload.get("ip") or ""),
                                   clearance.ip_fingerprint(ip)):
            return False, "bad_ip", "", 0, 0
        if not hmac.compare_digest(str(payload.get("ua") or ""),
                                   clearance.ua_fingerprint(ua)):
            return False, "bad_ua", "", 0, 0

        level = int(payload.get("lvl") or 1)
        challenge = str(payload.get("chal") or "")
        prefix = int(payload.get("pfx") or 0)
        if not challenge or not (1 <= prefix <= 6):
            return False, "invalid", "", 0, 0

        features = body.get("features")
        features = features if isinstance(features, dict) else {}
        auto_score, auto_reasons = score_features(features)
        hard = [r for r in auto_reasons if r in HARD_AUTOMATION]
        if hard:
            return False, "automation", "", 0, 0
        if auto_score >= site.challenge.automation_threshold:
            return False, "automation", "", 0, 0

        kind = str(body.get("pointer_type") or "").strip().lower()
        if kind == "synthetic":
            return False, "automation", "", 0, 0

        # 交互关卡：L2 起要求「手真的在框上」，L1 静默跳过
        need_gate = site.challenge.click_gate and level >= 2
        if need_gate:
            ok, reason, score = self._check_interaction(site, body, kind)
            if not ok:
                return False, reason, "", 0, 0
            auto_score += score

        try:
            nonce = int(body.get("nonce"))
        except (TypeError, ValueError):
            return False, "wrong", "", 0, 0
        if nonce < 0 or nonce > MAX_NONCE:
            return False, "wrong", "", 0, 0

        digest = hashlib.sha256((challenge + ":" + str(nonce)).encode()).hexdigest()
        if not digest.startswith("0" * prefix):
            return False, "wrong", "", 0, 0

        ttl = site.clearance.ttl_for(level)
        value, _exp = clearance.issue(
            self._key(site), site.sitekey, level, ttl, ip, ua,
            site.clearance.bind_ip, site.clearance.bind_ua)
        self.state.record(True, "cleared", site.sitekey)
        return True, "ok", value, ttl, level

    def _check_interaction(self, site: SiteCfg, body: dict,
                           kind: str) -> tuple[bool, str, int]:
        try:
            hold = int(body.get("hold_ms"))
        except (TypeError, ValueError):
            hold = 0
        points = norm_path_points(body.get("path"))

        if kind in ("touch", "pen"):
            if hold and hold < 20:
                return False, "interaction", 0
            return True, "ok", 0
        if kind == "key":
            return True, "ok", 0

        if len(points) < 2:
            return (True, "ok", 0) if hold >= 40 else (False, "interaction", 0)

        span = points[-1][2] - points[0][2]
        length = 0.0
        for i in range(1, len(points)):
            dx = points[i][0] - points[i - 1][0]
            dy = points[i][1] - points[i - 1][1]
            length += (dx * dx + dy * dy) ** 0.5
        if span < 20 or length < 4:
            return False, "interaction", 0
        if span > 0 and length / span * 1000 > 15000:
            return False, "interaction", 0

        m = track_metrics(points)
        if site.challenge.track_strict and m["score"] >= site.challenge.track_threshold:
            return False, "interaction", 0
        return True, "ok", m["score"]

    # ---------------------------------------------------------- 回跳校验
    def safe_redirect(self, cfg: Config, target: str, site: SiteCfg | None) -> str:
        """质询页上「过关后去哪」的唯一出口。只允许回到本站。

        这是防「拿本服务当跳板」的闸门：
          · 必须是本站相对路径，或同白名单域名的绝对地址；
          · 协议只认 http/https（挡 javascript: / data:）；
          · "//evil.com" 这类协议相对地址按绝对地址处理，一样要过白名单。

        代理模式下本来就用不到（过关后是 reload），但托管模式下这是唯一的闸门，
        所以无论如何都在这里收口，不给调用方「直接透传」的机会。
        """
        if not target:
            return "/"
        target = target.strip()
        if target.startswith("/") and not target.startswith("//"):
            return target
        from urllib.parse import urlparse
        try:
            parsed = urlparse(target)
        except ValueError:
            return "/"
        if parsed.scheme not in ("http", "https"):
            return "/"
        host = (parsed.hostname or "").lower()
        if not host:
            return "/"
        allowed = {h for h in cfg.sites if h not in ("*", "")}
        if host in allowed:
            return target
        if site is not None and site.host not in ("*", "") and host == site.host:
            return target
        log = __import__("logging").getLogger("pelacustoms.core")
        log.warning("拒绝回跳到非本站地址：%s", target)
        return "/"


MESSAGES = {
    "challenge": "需要先完成一次人机验证",
    "expired": "验证已过期，请重新验证",
    "bad_ip": "网络环境发生变化，请重新验证",
    "bad_ua": "浏览器信息发生变化，请重新验证",
    "bad_sitekey": "站点密钥不匹配",
    "unconfigured": "人机验证暂时不可用",
    "automation": "验证未通过，请刷新页面后重试",
    "interaction": "验证未通过，请按提示操作后再试",
    "wrong": "验证未通过，请重试",
    "invalid": "验证数据无效，请刷新后重试",
    "rate_limited": "请求过于频繁，请稍后再试",
}


def failure_message(reason: str) -> str:
    return MESSAGES.get(reason, "人机验证未通过，请重试")
