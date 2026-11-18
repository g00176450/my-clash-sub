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


def extract_api_candidates(html):
    cands = set()
    pats = [
        r"""fetch\(\s*['"`]([^'"`\$]+)['"`]""",
        r"""(?:axios|http)\.(?:get|post)\(\s*['"`]([^'"`\$]+)['"`]""",
        r"""['"](\/[a-zA-Z0-9_\/\-]{3,80})['"]""",
        r"""['"]([a-zA-Z0-9_\-]*api[a-zA-Z0-9_\-]*\/[a-zA-Z0-9_\/\-]*)['"]""",
    ]
    for pat in pats:
        for m in re.finditer(pat, html):
            path = m.group(1)
            if not path.startswith(("/v1/", "/v2/", "http", "#", "mailto")):
                continue
            if any(k in path.lower() for k in
                   ("api", "sub", "free", "clash", "vmess",
                    "hysteria", "ssr", "node", "daily")):
                cands.add(path)
            elif "/api/" in path or path.startswith("/api"):
                cands.add(path)
    return sorted(cands)


def try_api(s, path):
    url = path if path.startswith("http") else BASE + path
    h = {"X-Requested-With": "XMLHttpRequest",
         "Accept": "application/json, text/javascript, */*; q=0.01"}
    try:
        r = s.get(url, timeout=TIMEOUT, headers=h)
        body = r.text
        print("[API]", url, "->", r.status_code, "len:", len(body))
        ct = r.headers.get("content-type", "")
        if "json" in ct or body.strip().startswith(("{", "[")):
            try:
                return r.json()
            except Exception:
                pass
        if r.status_code == 200 and 0 < len(body) < 3000:
            print("[BODY]", body[:600])
    except Exception as e:
        print("[API-ERR]", url, str(e)[:100])
    return None


def find_sub_urls(obj, depth=0):
    out = []
    if depth > 6:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and (
                    "/v1/sub/" in v or v.startswith("http")):
                if k in ("subscription_url", "sub_url", "url",
                         "link", "subscriptionUrl"):
                    out.append(v)
            else:
                out.extend(find_sub_urls(v, depth + 1))
    elif isinstance(obj, list):
        for it in obj:
            out.extend(find_sub_urls(it, depth + 1))
    return out


def probe_common_paths(s):
    extra = [
        "/api/free_clash", "/api/sub/free", "/api/subscriptions",
        "/api/v1/subscriptions", "/ui/api/free_clash",
        "/api/clash/free", "/free_clash/api", "/api/free_sub",
        UI + "?json=1", UI + "?api=1",
    ]
    for p in extra:
        d = try_api(s, p)
        if d:
            subs = find_sub_urls(d)
            if subs:
                return subs
    return []


def test_node_tcp(node):
    host, port = node.get("server"), node.get("port")
    if not host or not port:
        return False
    try:
        with socket.create_connection((host, int(port)), timeout=TCPT):
            return True
    except Exception:
        return False


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


def process(url, s):
    r = s.get(url, timeout=TIMEOUT,
              headers={"User-Agent": "clash-verge/v2.0.0"})
    r.raise_for_status()
    body = r.text
    if "访问验证" in body:
        raise RuntimeError("subscription blocked")
    data = yaml.safe_load(body)
    if not isinstance(data, dict) or not data.get("proxies"):
        print("[DBG] body head 500:", body[:500])
        raise RuntimeError("no proxies in yaml")
    proxies = data["proxies"]
    print("[OK] got", len(proxies), "proxies")
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        alive = [n for n, ok in zip(proxies,
                 pool.map(test_node_tcp, proxies)) if ok]
    print("[OK] alive:", len(alive), "/", len(proxies))
    if not alive:
        print("[WARN] all dead, fallback to full list")
        alive = proxies
    write_clash_yaml(alive)
    write_v2ray_base64(alive)
    print("[CHECK] clash.yaml exists:", CLASH_OUT.exists())
    print("[DONE]")


def main():
    s = session()
    r = s.get(UI, timeout=TIMEOUT)
    r.raise_for_status()
    html = r.text
    print("[DBG] page length:", len(html))
    if "访问验证" in html:
        raise RuntimeError("cookie expired")

    m = re.search(r"/v1/sub/(?:vmess|hysteria2?|ssr)/\d+/[A-Za-z0-9_\-]{10,}",
                  html.replace("\\/", "/"))
    if m:
        url = m.group(0)
        print("[OK] direct regex hit:", url)
        process(url if url.startswith("http") else BASE + url, s)
        return

    print("[DBG] no direct match, extracting API candidates...")
    cands = extract_api_candidates(html)
    print("[DBG] candidates:", len(cands))
    for c in cands:
        print("   -", c)

    all_subs = []
    for path in cands:
        d = try_api(s, path)
        if not d:
            continue
        subs = find_sub_urls(d)
        if subs:
            print("[OK] found", len(subs), "subs in", path)
            for u in subs:
                print("   *", u)
            all_subs.extend(subs)

    if not all_subs:
        print("[DBG] trying common API paths...")
        all_subs = probe_common_paths(s)

    if not all_subs:
        print("[DBG] ===== full inline scripts =====")
        for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.S):
            body = m.group(1).strip()
            if body:
                print("---- script ----")
                print(body)
        raise RuntimeError("no api returned subscription, see scripts above")

    vmess = [u for u in all_subs if "/vmess/" in u]
    url = vmess[0] if vmess else all_subs[0]
    print("[OK] selected:", url)
    process(url, s)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[FAIL]", e, file=sys.stderr)
        sys.exit(1)
