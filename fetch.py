#!/usr/bin/env python3
"""fetch.py — Playwright 打开喵喵网站，自动完成计算题验证，提取订阅链接并抓节点"""

import re, json, base64, socket, logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests, yaml
from playwright.sync_api import sync_playwright

SITE_URL    = "https://www.freeclash.top/"
SITE_COOKIE = __import__("os").environ.get("FREECLASH_COOKIE", "").strip()
TCP_TIMEOUT, TCP_WORKERS = 5, 30
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
log = logging.info

# ---------- 1. 浏览器打开页面 + 自动做题 ----------
MATH_RE = re.compile(r"(\d+)\s*([+\-×x*])\s*(\d+)")

def solve_math(text: str):
    m = MATH_RE.search(text)
    if not m:
        return None
    a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
    return a + b if op in "+*" else a - b if op == "-" else None

def get_sub_url_via_browser():
    log("[BROWSER] 启动 Chromium...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
        ctx = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0")
        if SITE_COOKIE:
            cookies = []
            for kv in SITE_COOKIE.split(";"):
                k, _, v = kv.strip().partition("=")
                if k:
                    cookies.append({"name": k, "value": v, "domain": "www.freeclash.top", "path": "/"})
            if cookies:
                ctx.add_cookies(cookies)
                log(f"[COOKIE] 注入 {len(cookies)} 条")
        page = ctx.new_page()
        page.goto(SITE_URL, wait_until="domcontentloaded", timeout=60000)
        page.wait_for_timeout(3000)

        # 找计算题：常见形式是页面出现 "12 + 5 = ?" 和一个输入框 + 提交按钮
        body_text = page.inner_text("body")
        answer = solve_math(body_text)
        if answer is not None and page.locator("input[type=text], input[type=number], input:not([type])").count() > 0:
            log(f"[CAPTCHA] 检测到计算题，答案: {answer}")
            box = page.locator("input[type=text], input[type=number], input:not([type])").first
            box.fill(str(answer))
            # 找提交按钮
            for sel in ["button:has-text('提交')", "button:has-text('验证')", "button:has-text('确定')",
                        "input[type=submit]", "button"]:
                if page.locator(sel).count() > 0:
                    page.locator(sel).first.click()
                    break
            page.wait_for_timeout(3000)
            body_text = page.inner_text("body")
            log("[CAPTCHA] 已提交答案")
        else:
            log("[CAPTCHA] 未检测到计算题（可能已被 cookie 放行）")

        # 提取 vmess 订阅链接：优先从页面文本/属性找
        html = page.content()
        m = re.search(r'["\'(]([^"\'()]*?/v1/sub/vmess/[^"\'()\s<>]+)', html, re.IGNORECASE)
        if not m:
            # 链接可能由 JS 动态生成，再从渲染后的文本里找
            m = re.search(r"(https?://[^\s\"'<>]*?/v1/sub/vmess/[^\s\"'<>]+)", body_text, re.IGNORECASE)
        if not m:
            # 最后手段：点击 "复制订阅链接" 按钮，读剪贴板（需授权）
            page.evaluate("navigator.clipboard.writeText('').catch(()=>{})")
            btn = page.locator("button:has-text('复制订阅'), a:has-text('复制订阅')").first
            if btn.count() > 0:
                ctx.grant_permissions(["clipboard-read", "clipboard-write"])
                btn.click()
                page.wait_for_timeout(1000)
                clip = page.evaluate("navigator.clipboard.readText().catch(()=>'')")
                m = re.search(r"(https?://[^\s\"']+)", clip or "")
        browser.close()
        if not m:
            raise ValueError("验证后仍未找到 /v1/sub/vmess/ 链接")
        url = m.group(1)
        exp_m = re.search(r"/v1/sub/vmess/(\d+)/", url)
        exp = datetime.fromtimestamp(int(exp_m.group(1)), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if exp_m else "?"
        log(f"[BROWSER] 订阅链接（过期 {exp}）: {url[:80]}...")
        return url

# ---------- 2~5. 抓取/解析/测试/输出（与之前版本相同） ----------
def fetch_sub(url):
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 Chrome/120.0"})
    r = s.get(url, timeout=20); r.raise_for_status()
    text = r.text.strip()
    if "<html" in text.lower(): raise ValueError("订阅返回 HTML，链接可能已失效")
    return text

def parse_vmess_uri(uri):
    payload = uri[len("vmess://"):]
    try:
        obj = json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4), altchars=b"-_").decode("utf-8", "ignore"))
    except Exception:
        return None
    server, port, uuid = str(obj.get("add", "")), int(obj.get("port", 0) or 0), str(obj.get("id", ""))
    if not (server and port and uuid): return None
    node = {"name": str(obj.get("ps") or f"vmess-{server}:{port}"), "type": "vmess",
            "server": server, "port": port, "uuid": uuid,
            "alterId": int(obj.get("aid", 0) or 0), "cipher": obj.get("scy") or "auto", "udp": True}
    if str(obj.get("tls", "")).lower() in ("tls", "true", "1"):
        node["tls"] = True
        if obj.get("sni"): node["servername"] = obj["sni"]
    net = obj.get("net", "tcp") or "tcp"
    if net == "ws":
        node["network"] = "ws"
        ws = {"path": obj.get("path") or "/"}
        if obj.get("host"): ws["headers"] = {"Host": obj["host"]}
        node["ws-opts"] = ws
    elif net == "grpc":
        node["network"] = "grpc"; node["grpc-opts"] = {"grpc-service-name": obj.get("path", "")}
    return node

def parse_text(text):
    first = text.lstrip().splitlines()[0] if text.strip() else ""
    if re.search(r"^proxies:\s*$", text, re.MULTILINE):
        proxies = (yaml.safe_load(text) or {}).get("proxies") or []
        log(f"[PARSE] Clash YAML，{len(proxies)} 节点"); return proxies
    lines = text.splitlines()
    if first.startswith("vmess://"):
        pass
    else:
        lines = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_").decode("utf-8", "ignore").splitlines()
    out = []
    for l in lines:
        l = l.strip()
        if l.startswith("vmess://"):
            p = parse_vmess_uri(l)
            if p: out.append(p)
            else: log(f"[SKIP] {l[:50]}...")
    log(f"[PARSE] URI 模式，{len(out)} 节点"); return out

def tcp_alive(server, port):
    try:
        with socket.create_connection((server, port), timeout=TCP_TIMEOUT): return True
    except Exception: return False

def write_output(proxies):
    names = [p["name"] for p in proxies]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H:%M UTC")
    conf = {"mixed-port": 7890, "mode": "rule", "log-level": "info", "allow-lan": False,
            "proxies": proxies,
            "proxy-groups": [
                {"name": "PROXY", "type": "select", "proxies": ["AUTO"] + names},
                {"name": "AUTO", "type": "url-test", "proxies": names,
                 "url": "http://www.gstatic.com/generate_204", "interval": 300}],
            "rules": ["DOMAIN-SUFFIX,cn,DIRECT", "GEOIP,CN,DIRECT", "MATCH,PROXY"]}
    with open("clash.yaml", "w", encoding="utf-8") as f:
        f.write(f"# auto: update {now}\n"); yaml.safe_dump(conf, f, allow_unicode=True, sort_keys=False)
    log(f"[WRITE] clash.yaml ({len(proxies)} 节点)")
    lines = []
    for p in proxies:
        obj = {"v": "2", "ps": p["name"], "add": p["server"], "port": str(p["port"]), "id": p["uuid"],
               "aid": str(p.get("alterId", 0)), "net": p.get("network", "tcp"), "type": "none",
               "host": "", "path": "", "tls": "tls" if p.get("tls") else "", "scy": p.get("cipher", "auto")}
        if p.get("ws-opts"):
            obj["path"] = p["ws-opts"].get("path", "/"); obj["host"] = p["ws-opts"].get("headers", {}).get("Host", "")
        lines.append("vmess://" + base64.b64encode(json.dumps(obj, ensure_ascii=False).encode()).decode())
    with open("v2ray.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(lines).encode()).decode())
    log("[WRITE] v2ray.txt")

def main():
    url = get_sub_url_via_browser()
    text = fetch_sub(url)
    proxies = parse_text(text)
    if not proxies: log("[FAIL] 无节点"); raise SystemExit(2)
    seen, uniq = set(), []
    for p in proxies:
        k = (p["server"], p["port"])
        if k not in seen: seen.add(k); uniq.append(p)
    log(f"[DEDUPE] {len(proxies)} → {len(uniq)}")
    alive = []
    with ThreadPoolExecutor(max_workers=TCP_WORKERS) as pool:
        futs = {pool.submit(tcp_alive, p["server"], p["port"]): p for p in uniq}
        for f in as_completed(futs):
            if f.result(): alive.append(futs[f])
    log(f"[TCP] {len(uniq)} → {len(alive)} 存活")
    if not alive: log("[FAIL] 全部节点不可达"); raise SystemExit(3)
    write_output(alive)
    log(f"[DONE] 输出 {len(alive)} 个节点")

if __name__ == "__main__":
    main()
