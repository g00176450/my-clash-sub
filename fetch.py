#!/usr/bin/env python3
print("===== FETCH.PY START =====")

import base64, concurrent.futures, json, os, pathlib, re, socket, sys, time
import requests, yaml

BASE = "https://www.freeclash.top"
API = BASE + "/ui/api/clash_subscriptions"
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
    s.headers.update({
        "User-Agent": UA,
        "Referer": BASE + "/ui/free_clash",
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json",
    })
    s.cookies.update(get_cookie())
    return s


def get_subscription_urls(s):
    r = s.get(API, timeout=TIMEOUT)
    r.raise_for_status()
    print("[OK] API status:", r.status_code, "len:", len(r.text))
    data = r.json()
    subs = data.get("subscriptions", [])
    print("[OK] subscriptions count:", len(subs))
    for sub in subs:
        print("   -", sub.get("proxy_type", "?"), ":",
              str(sub.get("subscription_url", ""))[:80])
    urls = [sub["subscription_url"] for sub in subs
            if sub.get("subscription_url")]
    if not urls:
        print("[DBG] raw:", json.dumps(data, ensure_ascii=False)[:800])
        raise RuntimeError("no subscription_url in response")
    return urls


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
    body = "\n".join(lines).encode("utf-8")
    V2RAY_OUT.write_text(base64.b64encode(body).decode("ascii"),
                         encoding="utf-8")
    print("[OK] wrote v2ray.txt with", len(lines), "links")


def fetch_and_parse(s, url):
    r = s.get(url, timeout=TIMEOUT,
              headers={"User-Agent": "clash-verge/v2.0.0"})
    r.raise_for_status()
    body = r.text
    if "访问验证" in body:
        raise RuntimeError("subscription blocked: " + url)
    data = yaml.safe_load(body)
    if not isinstance(data, dict) or not data.get("proxies"):
        print("[DBG] body head:", body[:400])
        raise RuntimeError("no proxies in yaml from: " + url)
    print("[OK] got", len(data["proxies"]), "proxies from",
          url.split("/")[-1][:20])
    return data["proxies"]


def main():
    start = time.time()
    s = session()

    urls = get_subscription_urls(s)
    all_proxies = []
    for u in urls:
        try:
            all_proxies.extend(fetch_and_parse(s, u))
        except Exception as e:
            print("[WARN] skip url:", str(e)[:120])

    if not all_proxies:
        raise RuntimeError("no proxies from any subscription")

    # 按 (server, port, type) 去重
    seen, uniq = set(), []
    for p in all_proxies:
        key = (p.get("server"), p.get("port"), p.get("type"))
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    print("[OK] unique proxies:", len(uniq))

    print("[OK] testing alive...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        alive = [n for n, ok in zip(uniq, pool.map(test_node_tcp, uniq)) if ok]
    print("[OK] alive:", len(alive), "/", len(uniq))
    if not alive:
        print("[WARN] all dead, fallback to full list")
        alive = uniq

    write_clash_yaml(alive)
    write_v2ray_base64(alive)
    print("[CHECK] clash.yaml exists:", CLASH_OUT.exists())
    print("[DONE] elapsed:", round(time.time() - start, 1), "s")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[FAIL]", e, file=sys.stderr)
        sys.exit(1)
