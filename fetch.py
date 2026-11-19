#!/usr/bin/env python3
"""fetch.py (debug版) — Playwright 自动验证 + 失败时导出页面截图/HTML 供分析"""

import re, json, base64, socket, logging, os
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests, yaml
from playwright.sync_api import sync_playwright

SITE_URL    = "https://www.freeclash.top/ui/free_clash"
SITE_COOKIE = os.environ.get("FREECLASH_COOKIE", "").strip()
TCP_TIMEOUT, TCP_WORKERS = 5, 30
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
log = logging.info

MATH_RE = re.compile(r"(\d+)\s*([+\-×x*])\s*(\d+)")

def solve_math(text: str):
    m = MATH_RE.search(text)
    if not m: return None
    a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
    return a + b if op in "+*" else a - b if op == "-" else None

def try_solve_captcha(page):
    """在页面及所有 iframe 中找计算题并提交"""
    frames = [page.main_frame] + page.frames
    for i, fr in enumerate(frames):
        try:
            text = fr.inner_text("body")
        except Exception:
            continue
        ans = solve_math(text)
        inputs = fr.locator("input[type=text], input[type=number], input:not([type])")
        if ans is not None and inputs.count() > 0:
            log(f"[CAPTCHA] frame#{i} 检测到计算题，答案: {ans}")
            inputs.first.fill(str(ans))
            for sel in ["button:has-text('提交')", "button:has-text('验证')", "button:has-text('确定')",
                        "button:has-text('GO')", "input[type=submit]", "button"]:
                try:
                    if fr.locator(sel).count() > 0:
                        fr.locator(sel).first.click()
                        page.wait_for_timeout(3000)
                        log("[CAPTCHA] 已提交")
                        return True
                except Exception:
                    continue
    return False

def dump_debug(page, tag="fail"):
    """保存调试工件"""
    try:
        with open("debug_page.html", "w", encoding="utf-8") as f:
            f.write(page.content())
        with open("debug_text.txt", "w", encoding="utf-8") as f:
            f.write(page.inner_text("body"))
        page.screenshot(path="debug_screenshot.png", full_page=True)
        log(f"[DEBUG] 已保存 debug_screenshot.png / debug_page.html / debug_text.txt ({tag})")
        # 正文前 800 字直接打进日志，方便不下载文件也能看
        body = page.inner_text("body")
        log(f"[DEBUG] 页面正文前800字:\n{body[:800]}")
    except Exception as e:
        log(f"[DEBUG] 保存失败: {e}")

def get_sub_url_via_browser():
    log("[BROWSER] 启动 Chromium...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
        ctx = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                                  viewport={"width": 1280, "height": 900})
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
        page.goto(SITE_URL, wait_until="networkidle", timeout=60000)
        page.wait_for_timeout(3000)

        # 第一轮验证
        if not try_solve_captcha(page):
            log("[CAPTCHA] 第一轮未检测到计算题")
        # 有些站点提交后弹第二轮，再试一次
        page.wait_for_timeout(2000)
        try_solve_captcha(page)

        # 遍历所有 frame 找订阅链接
        html_all, text_all = "", ""
        for fr in page.frames:
            try:
                html_all += fr.content() + "\n"
                text_all += fr.inner_text("body") + "\n"
            except Exception:
                pass

        m = re.search(r'["\'(]([^"\'()]*?/v1/sub/vmess/[^"\'()\s<>]+)', html_all, re.IGNORECASE)
        if not m:
            m = re.search(r"(https?://[^\s\"'<>]*?/v1/sub/vmess/[^\s\"'<>]+)", text_all, re.IGNORECASE)
        if not m:
            # 兜底：找任何 /v1/sub/ 链接
            m = re.search(r'["\'(]([^"\'()]*?/v1/sub/[^"\'()\s<>]+)', html_all, re.IGNORECASE)
        if not m:
            dump_debug(page)
            browser.close()
            raise ValueError("验证后仍未找到订阅链接（已保存调试文件）")

        url = m.group(1)
        if not url.startswith("http"):
            url = "https://www.freeclash.top" + (url if url.startswith("/") else "/" + url)
        exp_m = re.search(r"/v1/sub/vmess/(\d+)/", url)
        exp = datetime.fromtimestamp(int(exp_m.group(1)), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if exp_m else "?"
        log(f"[BROWSER] 订阅链接（过期 {exp}）: {url[:90]}...")
        browser.close()
        return url

# ---------- 以下与之前版本相同 ----------
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
    if not first.startswith("vmess://"):
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
