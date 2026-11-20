import ipaddress
from pathlib import Path
import re
import tempfile
from urllib.parse import urlparse
import requests

SOURCES = [
    # Domain rules
    (
        "domain",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/private.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/douyin.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/tiktok.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/telegram.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-social-media-!cn.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/youtube.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/netflix.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/microsoft@cn.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/microsoft.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/apple.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-games.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/paypal.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-cryptocurrency.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/google.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/ookla-speedtest.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/Gavinuuup/Mihomo/main/rules/domain/Proxy.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/Gavinuuup/Mihomo/main/rules/domain/cn.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/Gavinuuup/Mihomo/main/rules/domain/Streaming-cn.list",
    ),
    (
        "domain",
        "https://raw.githubusercontent.com/Gavinuuup/Mihomo/main/rules/domain/AI.list",
    ),
    # IP rules
    (
        "ip",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/private.list",
    ),
    (
        "ip",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/telegram.list",
    ),
    (
        "ip",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/facebook.list",
    ),
    (
        "ip",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/twitter.list",
    ),
    (
        "ip",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/netflix.list",
    ),
    (
        "ip",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/google.list",
    ),
    (
        "ip",
        "https://raw.githubusercontent.com/Gavinuuup/Mihomo/main/rules/ip/cn.list",
    ),
    (
        "ip",
        "https://raw.githubusercontent.com/Gavinuuup/Mihomo/main/rules/ip/AI.list",
    ),
]

DOMAIN_TYPE_MAP = {
    "DOMAIN": "HOST",
    "HOST": "HOST",
    "DOMAIN-SUFFIX": "HOST-SUFFIX",
    "HOST-SUFFIX": "HOST-SUFFIX",
    "DOMAIN-KEYWORD": "HOST-KEYWORD",
    "HOST-KEYWORD": "HOST-KEYWORD",
    "DOMAIN-REGEX": "HOST-REGEX",
    "HOST-REGEX": "HOST-REGEX",
}


def detect_ip_type(value: str) -> str | None:
    try:
        net = ipaddress.ip_network(value, strict=False)
        return "IP-CIDR6" if net.version == 6 else "IP-CIDR"
    except ValueError:
        return None


def convert_line(line: str, kind: str, policy: str) -> str | None:
    s = line.strip()
    if not s or s.startswith(("#", "//", ";")):
        return None
    if s.startswith("- "):
        s = s[2:].strip().strip("'\"")

    # 去掉行内注释
    s = re.split(r"\s+#|\s+//", s, maxsplit=1)[0].strip()
    if not s:
        return None

    parts = [p.strip() for p in s.split(",")]

    if kind == "ip":
        if len(parts) == 1:
            ip_type = detect_ip_type(parts[0])
            return f"{ip_type},{parts[0]},{policy}" if ip_type else None
        rtype = parts[0].upper()
        val = parts[1]
        if rtype in ("IP-CIDR", "IP-CIDR6"):
            ip_type = detect_ip_type(val) or rtype
            has_no_resolve = any(p.lower() == "no-resolve" for p in parts[2:])
            suffix = ",no-resolve" if has_no_resolve else ""
            return f"{ip_type},{val},{policy}{suffix}"
        return None

    # kind == "domain"
    if len(parts) == 1:
        val = parts[0]
        # 兼容部分规则集里混入的 IP/CIDR
        ip_type = detect_ip_type(val)
        if ip_type:
            return f"{ip_type},{val},{policy}"
        if val.startswith("+."):
            return f"HOST-SUFFIX,{val[2:]},{policy}"
        if val.startswith("*."):
            return f"HOST-SUFFIX,{val[2:]},{policy}"
        return f"HOST-SUFFIX,{val},{policy}"

    rtype = parts[0].upper()
    val = parts[1]
    if rtype in DOMAIN_TYPE_MAP:
        return f"{DOMAIN_TYPE_MAP[rtype]},{val},{policy}"
    if rtype in ("IP-CIDR", "IP-CIDR6"):
        ip_type = detect_ip_type(val) or rtype
        has_no_resolve = any(p.lower() == "no-resolve" for p in parts[2:])
        suffix = ",no-resolve" if has_no_resolve else ""
        return f"{ip_type},{val},{policy}{suffix}"

    return None


def main() -> None:
    headers = {"User-Agent": "Mozilla/5.0 (compatible; MihomoToQX/1.0)"}
    with tempfile.TemporaryDirectory() as tmp:
        raw_dir = Path(tmp)
        for idx, (kind, url) in enumerate(SOURCES):
            filename = Path(urlparse(url).path).name  # e.g. telegram.list
            policy = Path(filename).stem  # e.g. telegram
            raw_file = raw_dir / f"{kind}_{idx}_{filename}"
            out_dir = Path("Rule") / ("domain" if kind == "domain" else "ip")
            out_file = out_dir / filename

            try:
                resp = requests.get(url, headers=headers, timeout=20)
                resp.raise_for_status()
                raw_file.write_text(resp.text, encoding="utf-8")
            except Exception as exc:
                print(f"[WARN] Fetch failed for {url}: {exc}")
                continue

            rules = set()
            for line in raw_file.read_text(encoding="utf-8").splitlines():
                converted = convert_line(line, kind=kind, policy=policy)
                if converted:
                    rules.add(converted)

            out_dir.mkdir(parents=True, exist_ok=True)
            sorted_rules = sorted(rules)
            content = (
                f"# Source: {url}\n"
                f"# Policy: {policy}\n"
                f"# Total: {len(sorted_rules)}\n\n"
                + "\n".join(sorted_rules)
                + ("\n" if sorted_rules else "")
            )
            out_file.write_text(content, encoding="utf-8")
            print(f"[OK] {out_file} ({len(sorted_rules)} rules)")


if __name__ == "__main__":
    main()
