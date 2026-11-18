#!/usr/bin/env python3
print("===== FETCH.PY START =====")   # 模块级标记：只要被执行就一定出现

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
REGION_FILTER = []   # 例: ["香港","日本"] 留空不过滤

REPO_DIR  = pathlib.Path(__file__).parent
CLASH_OUT = REPO_DIR / "clash.yaml"
V2RAY_OUT = REPO_DIR / "v2ray.txt"


def get_cookie():
    raw = os.environ.get("FREECLASH_COOKIE", "").strip()
    if not raw:
        raise RuntimeError("Cookie 为空：检查 Secrets FREECLASH_COOKIE")
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
    # 还原 JSON/HTML 中的转义斜杠（此前未命中的最大嫌疑）
    html = (r.text.replace('\\/', '/')
                  .replace('&#x2F;', '/')
                  .replace('%2F', '/'))
    print(f"[DEBUG] UI 页长度: {len(html)}")
    if "访问验证" in html:
        raise RuntimeError("Cookie 失效：重新抓 Cookie 并更新 Secrets")

    found = re.findall(
        r'/v1/sub/(vmess|hysteria2?|ssr)/(\d+)/([A-Za-z0-9\-_]{10,})', html)
    print(f"[DEBUG] 页面命中 {len(found)} 条订阅链接:")
    for proto, ts, tok in found:
        print(f"[DEBUG]   {proto:9s} ts={ts} token={tok[:8]}...")

    m = re.search(r'/v1/sub/vmess/(\d+)/([A-Za-z0-9\-_]{10,})', html)
    if m:
        url = f"{BASE_URL}/v1/sub/vmess/{m.group(1)}/{m.group(2)}"
        print(f"[OK] 选用 vmess 订阅: {url}")
        return url
    m2 = re.search(r'/v1/sub/(?:hysteria2?|ssr)/(\d+)/([A-Za-z0-9\-_]{10,})', html)
    if m2:
        print(f"[WARN] 未找到 vmess，退回: {BASE_URL}{m2.group(0)}")
        return f"{BASE_URL}{m2.group(0)}"
    print("[DEBUG] ===== Page HE
