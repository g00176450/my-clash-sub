#!/usr/bin/env python3
import base64, concurrent.futures, json, os, pathlib, re, socket, sys, time
from datetime import datetime
import requests, yaml

BASE_URL = "https://www.freeclash.top"
UI_PATH  = f"{BASE_URL}/ui/free_clash"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
TIMEOUT = 20
MAX_WORKERS = 30
TCP_TIMEOUT = 3
REGION_FILTER = []   # 例: ["HK","JP","SG"] 按需填，留空不过滤

REPO_DIR  = pathlib.Path(__file__).parent
CLASH_OUT = REPO_DIR / "clash.yaml"
V2RAY_OUT = REPO_DIR / "v2ray.txt"

def get_cookie() -> dict:
    raw = os.environ.get("FREECLASH_COOKIE", "").strip()
    if not raw:
        raise RuntimeError("Cookie 为空：请在 GitHub Secrets 配置 FREECLASH_COOKIE")
    cookies = {}
    for pair in raw.replace("\n", ";").split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies

def build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": UA,
        "Referer": BASE_URL,
        "Accept": "text/html,application/json,*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    })
    s.cookies.update(get_cookie())
    return s

def fetch_daily_url(s) -> str:
    r = s.get(UI_PATH, timeout=TIMEOUT)
    r.raise_for_status()
    if "访问验证" in r.text:
        raise RuntimeError("Cookie 失效：请重新抓取 Cookie 并更新 Secrets")
    m = re.search(r'/v1/sub/vmess/(\d+)/([A-Za-z0-9\-_]{20,})', r.text)
    if m:
        return f"{BASE_URL}{m.group(0)}"
    m2 = re.search(r'https?://[^\s"\']+?/v1/sub/vmess/\d+/[A-Za-z0-9\-_]{20,}', r.text)
    if m2:
        return m2.group(0)
    raise RuntimeError("未匹配到订阅链接：站点结构可能已改版")

def download_yaml(s, url: str) -> dict:
    r = s.get(url, timeout=TIMEOUT)
    r.raise_for_status()
    if "访问验证" in r.text:
        raise RuntimeError("订阅 URL 被验证拦截：请检查 Cookie")
    data = yaml.safe_load(r.text)
    if not data or "proxies" not in data or not data["proxies"]:
        raise RuntimeError("YAML 中没有 proxies 节点")
    return data

def test_node_tcp(node: dict) -> bool:
    host, port = node.get("server"), node.get("port")
    if not host or not port:
        return False
    try:
        with socket.create_connection((host, int(port)), timeout=TCP_TIMEOUT):
            return True
    except Exception:
        return False

def filter_alive(proxies: list) -> list:
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        return [n for n, ok in zip(proxies, pool.map(test_node_tcp, proxies)) if ok]

def filter_region(proxies: list) -> list:
    if not REGION_FILTER:
        return proxies
    out = [p for p in proxies
           if any(k.lower() in (p.get("name") or "").lower() for k in REGION_FILTER)]
    return out or proxies

def write_clash_yaml(proxies: list):
    names = [p["name"] for p in proxies]
    out = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select",
             "proxies": ["♻️ 自动选择"] + names},
            {"name": "♻️ 自动选择", "type": "url-test",
             "proxies": names,
             "url": "http://www.gstatic.com/generate_204",
             "interval": 300},
        ],
        "rules": [
            "DOMAIN-SUFFIX,cn,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,🚀 节点选择",
        ],
    }
    CLASH_OUT.write_text(yaml.dump(out, allow_unicode=True, sort_keys=False),
                         encoding="utf-8")

def write_v2ray_base64(proxies: list):
    lines = []
    for p in proxies:
        t = p.get("type")
        if t == "vmess":
            vm = {
                "v": "2", "ps": p.get("name", ""),
                "add": p.get("server", ""), "port": str(p.get("port", "")),
                "id": p.get("uuid", ""), "aid": str(p.get("alterId", 0)),
                "net": p.get("network", "tcp"), "type": "none",
                "host": p.get("servername", "") or p.get("server", ""),
                "path": (p.get("ws-opts") or {}).get("path", "/"),
                "tls": "tls" if p.get("tls") else "", "scy": "auto",
            }
            lines.append("vmess://" + base64.b64encode(
                json.dumps(vm, ensure_ascii=False).encode()).decode())
        elif t == "ss":
            raw = f"{p.get('cipher')}:{p.get('password')}@{p.get('server')}:{p.get('port')}"
            lines.append("ss://" + base64.b64encode(raw.encode()).decode()
                         + f"#{p.get('name','')}")
    if lines:
        body = "\n".join(lines).encode()
        V2RAY_OUT.write_text(base64.b64encode(body).decode(), encoding="utf-8")

def main():
    start = time.time()
    print(f"[{datetime.now()}] Start...")
    s = build_session()
    daily_url = fetch_daily_url(s)
    print(f"[OK] Daily URL: {daily_url}")
    data = download_yaml(s, daily_url)
    proxies = filter_region(data["proxies"])
    print(f"[OK] Got {len(proxies)} proxies, testing...")
    alive = filter_alive(proxies)
    print(f"[OK] Alive: {len(alive)}/{len(proxies)}")
    if not alive:
        print("[WARN] All dead, fallback to full list")
        alive = proxies
    write_clash_yaml(alive)
    write_v2ray_base64(alive)
    print(f"[DONE] {time.time()-start:.1f}s")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[FAIL] {e}", file=sys.stderr)
        sys.exit(1)
