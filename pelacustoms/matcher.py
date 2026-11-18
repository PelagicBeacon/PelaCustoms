"""路径归一化与匹配。

这是整套东西最容易被绕过的地方，所以规则写死在这里、并且有专门的用例覆盖
（见 tests/test_flow.py 的「归一化」一组）：

1. 只取原始 URI（nginx 的 $request_uri），丢掉 query 和 fragment；
2. 先 URL 解码，再判 ".." 穿越 —— 顺序反了 %2e%2e 就能穿过去；
3. 合并连续斜杠、去掉尾斜杠（根路径除外）；
4. 大小写敏感（不做小写化，免得和上游路由规则打架）。

glob 规则："*" 不跨 "/"，"**" 跨 "/"，"?" 匹配单个非 "/" 字符；
"re:" 前缀走正则（逃生口）。
"""
from __future__ import annotations

import re
from urllib.parse import unquote


def normalize_path(uri: str) -> str:
    """把任意 URI 压成一个规范的、可安全用于匹配的路径。"""
    if not uri:
        return "/"
    raw = uri.split("#", 1)[0].split("?", 1)[0]
    if not raw.startswith("/"):
        raw = "/" + raw

    # 只解码一次：与 nginx $uri 的行为一致。多次解码会让合法的 %25 变成 %，
    # 反而制造出原本不存在的路径。
    try:
        decoded = unquote(raw, errors="strict")
    except (UnicodeDecodeError, ValueError):
        decoded = raw

    parts: list[str] = []
    for seg in decoded.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    return "/" + "/".join(parts)


def _glob_to_regex(pattern: str) -> str:
    """glob 转正则。末尾的 /** 同时匹配目录本身（含空目录）。"""
    triple = "/**"
    if pattern.endswith(triple) and len(pattern) > len(triple):
        head = pattern[: -len(triple)]
        return "^" + _glob_body(head) + "(/.*)?$"
    if pattern == triple or pattern == "**":
        return "^/.*$"
    return "^" + _glob_body(pattern) + "$"


def _glob_body(pattern: str) -> str:
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern.startswith("**", i):
                i += 2
                if pattern.startswith("/", i):      # 「**/」允许零级目录
                    out.append("(?:.*/)?")
                    i += 1
                else:
                    out.append(".*")
            else:
                out.append("[^/]*")
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return "".join(out)


class PatternSet:
    """一组预编译的路径模式。判定时只做正则匹配，不碰磁盘、不做字符串拼接。"""

    __slots__ = ("_rules", "_raw")

    def __init__(self, patterns: list[str]):
        self._raw = tuple(patterns)
        self._rules = []
        for pat in patterns:
            if pat.startswith("re:"):
                self._rules.append(re.compile(pat[3:]))
            else:
                self._rules.append(re.compile(_glob_to_regex(pat)))

    def matches(self, path: str) -> bool:
        for rule in self._rules:
            if rule.match(path):
                return True
        return False

    def __repr__(self) -> str:
        return "PatternSet(" + repr(list(self._raw)) + ")"


def is_excluded(path: str, exclude: PatternSet) -> bool:
    """排除判定必须排在触发判定之前，否则 /static/** 里的东西也会被质询。"""
    return exclude.matches(path)


def is_protected(path: str, include: PatternSet, exclude: PatternSet,
                 method: str, methods) -> bool:
    if method.upper() not in methods:
        return False
    if is_excluded(path, exclude):
        return False
    return include.matches(path)
