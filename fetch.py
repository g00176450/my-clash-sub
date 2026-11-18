#!/usr/bin/env python3
print("===== FETCH.PY START =====")

import base64, concurrent.futures, json, os, pathlib, re, socket, sys, time
import requests, yaml

BASE = "https://www.freeclash.top"
UI = BASE + "/ui/free_clash"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
TIMEOUT = 20
WORKERS = 30
TCPT = 3
HERE = pathlib.Path(__file__).parent
CLASH_OUT = HERE / "clash.yaml"
V2RAY_OUT = HERE / "v2ray.txt"
LINK_RE = r"/v1/sub/(?:vmess|hysteria2?|ssr)/\d+/[A-Za-z0-9_\-]{10,}"


def get_cookie():
    raw = os.environ.get("FREECLASH_COOKIE", "").strip()
    if not raw:
        raise RuntimeError("cookie empty")
    out = {}
    for p in raw.replace("\n", ";").split(";"):
        if "=" in p:
            k, v = p.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def session():
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Referer": BASE,
                      "Accept-Language": "zh-CN,zh;q=0.9"})
    s.cookies.update(get_cookie())
    return s


def variants(html):
    yield "raw", html
    yield "slash", html.replace("\\/", "/")
    yield "entity", html.replace("&#x2F;", "/").replace("&#47;", "/")
    yield "unicode", html.replace("\\u002f", "/").replace("\\u002F", "/")
    stripped = re.sub(r"<[^>]+>", " ", html).replace("\\/", "/")
    yield "stripped", stripped


def find_link(html):
    for name, text in variants(html):
        m = re.search(LINK_RE, text)
        if m:
            print("[OK] matched in variant:", name)
            url = m.group(0)
            return url if url.startswith("http") else BASE + url
        print("[DBG] variant", name, "-> no match")
    return None


def dump_diagnostics(html):
    print("[DBG] ---- keyword context (120 chars before / 180 after) ----")
    for kw in ["vmess", "hysteria", "/v1/", "subscription", "copy", "qr"]:
        hits = [m.start() for m in re.finditer(re.escape(kw), html)][:5]
        print("[DBG] keyword", repr(kw), "occurrences:", len(hits))
        for i in hits:
            seg = html[max(0, i - 120):i + 180].replace("\n", " ")
            print("[CTX]", seg)
    print("[DBG] ---- inline script blocks ----")
    for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.S):
        body = m.group(1).strip()
        if body:
            print("[SCRIPT]", body[:1200])
            print("[/SCRIPT]")
    print("[DBG] ---- page body chars 2000..12000 ----")
    print(html[2000:12000])


def download_yaml(url):
    r = s.get(url, timeout=TIMEOUT, headers={"User-Agent": "clash-verge/v2.0.0"})
    r.raise_for_status()
    body = r.text
    if "访问验证" in body:
        raise RuntimeError("subscription blocked")
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
        with socket.create_connection((host, int(port)), timeout=TCPT):
            return True
    except Exception:
        return False


def filter_alive(proxies):
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        return [n for n, ok in zip(proxies, pool.map(test_node_tcp, proxies)) if ok]


def write_clash_yaml(proxies):
    names = [p["name"] for p in proxies]
    out = {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule",
        "log-level": "info", "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO"] + names},
            {"name": "AUTO", "type": "url-test", "proxies": names,
             "url": "http://www.gstatic.com/generate_204", "interval": 300},
        ],
        "rules": ["DOMAIN-SUFFIX,cn,DIRECT", "GEOIP,CN,DIRECT", "MATCH,PROXY"],
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
                vm = {"v": "2", "ps": p.get("name", ""),
                      "add": p.get("server", ""), "port": str(p.get("port", "")),
                      "id": p.get("uuid", ""), "aid": str(p.get("alterId", 0)),
                      "net": p.get("network", "tcp"), "type": "none",
                      "host": p.get("servername", "") or p.get("server", ""),
                      "path": (p.get("ws-opts") or {}).get("path", "/"),
                      "tls": "tls" if p.get("tls") else "", "scy": "auto"}
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
        except Exception as e:
            print("[WARN] convert failed:", t, e)
    V2RAY_OUT.write_text(
        base64.b64encode("\n".join(lines).encode()).decode(), encoding="utf-8")
    print("[OK] wrote v2ray.txt with", len(lines), "links")


s = session()
r = s.get(UI, timeout=TIMEOUT)
r.raise_for_status()
html = r.text
print("[DBG] page length:", len(html))
if "访问验证" in html:
    raise RuntimeError("cookie expired")

url = find_link(html)
if not url:
    dump_diagnostics(html)
    raise RuntimeError("no link matched, see diagnostics above")
print("[OK] daily url:", url)

data = download_yaml(url)
proxies = data["proxies"]
print("[OK] testing", len(proxies), "nodes...")
alive = filter_alive(proxies)
print("[OK] alive:", len(alive), "/", len(proxies))
if not alive:
    print("[WARN] all dead, fallback to full list")
    alive = proxies
write_clash_yaml(alive)
write_v2ray_base64(alive)
print("[CHECK] clash.yaml exists:", CLASH_OUT.exists())
print("[DONE]")
