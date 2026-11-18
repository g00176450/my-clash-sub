#!/usr/bin/env python3
print("===== FETCH.PY START =====")

import base64, concurrent.futures, json, os, pathlib, re, socket, sys, time
import requests, yaml

BASE_URL = "https://www.freeclash.top"
UI_PATH  = BASE_URL + "/ui/free_clash"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
TIMEOUT = 20
MAX_WORKERS = 30
TCP_TIMEOUT = 3
REGION_FILTER = []

HERE = pathlib.Path(__file__).parent
CLASH_OUT = HERE / "clash.yaml"
V2RAY_OUT = HERE / "v2ray.txt"


def get_cookie():
    raw = os.environ.get("FREECLASH_COOKIE", "").strip()
    if not raw:
        raise RuntimeError("Cookie empty: check secret FREECLASH_COOKIE")
    cookies = {}
    for pair in raw.replace("\n", ";").split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def build_session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": UA,
        "Referer": BASE_URL,
        "Accept": "text/html,application/json,*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    })
    s.cookies.update(get_cookie())
    return s


def fetch_daily_url(s):
    r = s.get(UI_PATH, timeout=TIMEOUT)
    r.raise_for_status()
    html = r.text.replace("\\/", "/").replace("&#x2F;", "/").replace("%2F", "/")
    print("[DEBUG] page length:", len(html))
    if "访问验证" in html:
        raise RuntimeError("Cookie expired: update secret FREECLASH_COOKIE")

    found = re.findall(
        r"/v1/sub/(vmess|hysteria2?|ssr)/(\d+)/([A-Za-z0-9\-_]{10,})", html)
    print("[DEBUG] matched subscriptions:", len(found))
    for proto, ts, tok in found:
        print("[DEBUG]  ", proto, ts, tok[:8])

    m = re.search(r"/v1/sub/vmess/(\d+)/([A-Za-z0-9\-_]{10,})", html)
    if m:
        url = BASE_URL + "/v1/sub/vmess/" + m.group(1) + "/" + m.group(2)
        print("[OK] vmess url:", url)
        return url
    m2 = re.search(r"/v1/sub/(?:hysteria2?|ssr)/(\d+)/([A-Za-z0-9\-_]{10,})", html)
    if m2:
        url = BASE_URL + m2.group(0)
        print("[WARN] fallback url:", url)
        return url

    print("[DEBUG] page head 2000:")
    print(html[:2000])
    raise RuntimeError("no subscription link matched, see DEBUG above")


def download_yaml(s, url):
    r = s.get(url, timeout=TIMEOUT, headers={"User-Agent": "clash-verge/v2.0.0"})
    r.raise_for_status()
    body = r.text
    if "访问验证" in body:
        raise RuntimeError("subscription blocked by verify page")
    data = yaml.safe_load(body)
    if not isinstance(data, dict) or not data.get("proxies"):
        print("[DEBUG] body head 500:")
        print(body[:500])
        raise RuntimeError("no proxies in yaml")
    print("[OK] proxies:", len(data["proxies"]))
    return data


def test_node_tcp(node):
    host, port = node.get("server"), node.get("port")
    if not host or not port:
        return False
    try:
        with socket.create_connection((host, int(port)), timeout=TCP_TIMEOUT):
            return True
    except Exception:
        return False


def filter_alive(proxies):
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        return [n for n, ok in zip(proxies, pool.map(test_node_tcp, proxies)) if ok]


def write_clash_yaml(proxies):
    names = [p["name"] for p in proxies]
    out = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO"] + names},
            {"name": "AUTO", "type": "url-test", "proxies": names,
             "url": "http://www.gstatic.com/generate_204", "interval": 300},
        ],
        "rules": [
            "DOMAIN-SUFFIX,cn,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,PROXY",
        ],
    }
    CLASH_OUT.write_text(
        yaml.dump(out, allow_unicode=True, sort_keys=False), encoding="utf-8")
    print("[OK] wrote clash.yaml with", len(proxies), "proxies")


def write_v2ray_base64(proxies):
    lines = []
    for p in proxies:
        t = p.get("type")
        try:
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
                raw = "%s:%s@%s:%s" % (p.get("cipher"), p.get("password"),
                                       p.get("server"), p.get("port"))
                lines.append("ss://" + base64.b64encode(raw.encode()).decode()
                             + "#" + str(p.get("name", "")))
            elif t == "hysteria2":
                q = []
                if p.get("sni"):
                    q.append("sni=" + str(p["sni"]))
                if p.get("skip-cert-verify"):
                    q.append("insecure=1")
                query = ("?" + "&".join(q)) if q else ""
                lines.append("hysteria2://%s@%s:%s%s#%s" % (
                    p.get("password"), p.get("server"), p.get("port"),
                    query, p.get("name", "")))
            elif t == "trojan":
                q = ("?sni=" + str(p["sni"])) if p.get("sni") else ""
                lines.append("trojan://%s@%s:%s%s#%s" % (
                    p.get("password"), p.get("server"), p.get("port"),
                    q, p.get("name", "")))
            else:
                print("[WARN] skip node type:", t)
        except Exception as e:
            print("[WARN] convert failed:", t, e)
    V2RAY_OUT.write_text(
        base64.b64encode("\n".join(lines).encode()).decode(), encoding="utf-8")
    print("[OK] wrote v2ray.txt with", len(lines), "links")


def main():
    start = time.time()
    s = build_session()
    url = fetch_daily_url(s)
    data = download_yaml(s, url)
    proxies = data["proxies"]
    if REGION_FILTER:
        kept = [p for p in proxies
                if any(k.lower() in str(p.get("name", "")).lower()
                       for k in REGION_FILTER)]
        if kept:
            proxies = kept
    print("[OK] testing", len(proxies), "nodes...")
    alive = filter_alive(proxies)
    print("[OK] alive:", len(alive), "/", len(proxies))
    if not alive:
        print("[WARN] all dead, fallback to full list")
        alive = proxies
    write_clash_yaml(alive)
    write_v2ray_base64(alive)
    ok = CLASH_OUT.exists()
    print("[CHECK] clash.yaml exists:", ok)
    if not ok:
        raise RuntimeError("clash.yaml missing")
    print("[DONE] elapsed:", round(time.time() - start, 1), "s")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[FAIL]", e, file=sys.stderr)
        sys.exit(1)
