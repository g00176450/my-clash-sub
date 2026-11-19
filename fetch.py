#!/usr/bin/env python3
"""
fetch.py — 抓取喵喵订阅源，去重 + TCP 测试，输出 clash.yaml / v2ray.txt
数据源完全来自环境变量 MIAOMIAO_SUB_URL（单一来源，路线 B）
"""

import os
import re
import json
import base64
import socket
import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, unquote

import requests
import yaml

# ---------- 配置 ----------
SUB_URL      = os.environ.get("MIAOMIAO_SUB_URL", "").strip()
FETCH_TIMEOUT = 20
TCP_TIMEOUT   = 5
TCP_WORKERS   = 30
UA = "clash-meta/v2.0"

logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
log = logging.info


# ---------- 1. 拉取 ----------
def fetch_subscription(url: str) -> str:
    """拉取订阅原文，识别验证页 / 错误页 / 空响应"""
    r = requests.get(url, headers={"User-Agent": UA, "Accept": "*/*"},
                     timeout=FETCH_TIMEOUT, allow_redirects=True)
    r.raise_for_status()
    text = r.text.strip()
    if not text:
        raise ValueError("订阅返回为空")
    low = text.lower()
    if "<html" in low or "<!doctype" in low:
        raise ValueError("返回 HTML —— 订阅可能被验证码/防爬拦截，token 可能已失效")
    if "访问验证" in text or "captcha" in low or "请登录" in text:
        raise ValueError("返回验证/登录页 —— 重新去喵喵获取一个新的订阅链接")
    if text.startswith("{") and len(text) < 500 and '"error"' in low:
        raise ValueError(f"订阅返回错误 JSON: {text[:200]}")
    return text


# ---------- 2. 格式检测 ----------
def detect_format(text: str) -> str:
    if re.search(r"^proxies:\s*$", text, re.MULTILINE):
        return "yaml"
    first = text.lstrip().splitlines()[0] if text.strip() else ""
    if first.startswith(("vmess://", "ss://", "trojan://", "vless://")):
        return "uri_list"
    return "base64"


# ---------- 3. Clash YAML 解析 ----------
def parse_clash_yaml(text: str) -> list:
    data = yaml.safe_load(text)
    proxies = (data or {}).get("proxies") or []
    log(f"[PARSE] Clash YAML 模式，{len(proxies)} 个节点")
    return proxies


# ---------- 4. URI / Base64 解析 ----------
def parse_uri_list(lines: list) -> list:
    proxies = []
    for line in lines:
        try:
            if line.startswith("vmess://"):
                p = parse_vmess_uri(line)
            elif line.startswith("ss://"):
                p = parse_ss_uri(line)
            elif line.startswith("trojan://"):
                p = parse_trojan_uri(line)
            else:
                log(f"[SKIP] 未支持的协议: {line[:40]}...")
                continue
            if p:
                proxies.append(p)
        except Exception as e:
            log(f"[SKIP] 解析失败 {line[:40]}... : {e}")
    return proxies


def parse_base64_sub(text: str) -> list:
    padded = text + "=" * (-len(text) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_").decode("utf-8", "ignore")
    except Exception as e:
        raise ValueError(f"base64 解码失败: {e}")
    lines = [l.strip() for l in decoded.splitlines() if l.strip()]
    log(f"[PARSE] Base64 分享链接模式，{len(lines)} 行")
    return parse_uri_list(lines)


def parse_vmess_uri(uri: str):
    payload = uri[len("vmess://"):]
    padded = payload + "=" * (-len(payload) % 4)
    try:
        obj = json.loads(base64.b64decode(padded, altchars=b"-_")
                         .decode("utf-8", "ignore"))
    except Exception:
        return None
    server, port, uuid = str(obj.get("add", "")), int(obj.get("port", 0) or 0), str(obj.get("id", ""))
    if not (server and port and uuid):
        return None
    node = {
        "name": str(obj.get("ps") or f"vmess-{server}:{port}"),
        "type": "vmess",
        "server": server, "port": port, "uuid": uuid,
        "alterId": int(obj.get("aid", 0) or 0),
        "cipher": obj.get("scy") or "auto",
        "udp": True,
    }
    if str(obj.get("tls", "")).lower() in ("tls", "true", "1"):
        node["tls"] = True
        if obj.get("sni"):
            node["servername"] = obj["sni"]
    net = obj.get("net", "tcp") or "tcp"
    if net == "ws":
        node["network"] = "ws"
        ws = {"path": obj.get("path") or "/"}
        if obj.get("host"):
            ws["headers"] = {"Host": obj["host"]}
        node["ws-opts"] = ws
    elif net == "grpc":
        node["network"] = "grpc"
        node["grpc-opts"] = {"grpc-service-name": obj.get("path", "")}
    elif net == "tcp" and str(obj.get("type", "")).lower() == "http":
        node["network"] = "http"
        http = {"method": "GET", "path": [obj.get("path") or "/"]}
        if obj.get("host"):
            http["host"] = [obj["host"]]
        node["http-opts"] = http
    return node


def parse_ss_uri(uri: str):
    body = uri[len("ss://"):]
    name = ""
    if "#" in body:
        body, name = body.split("#", 1)
        name = unquote(name)
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        padded = userinfo + "=" * (-len(userinfo) % 4)
        try:
            cred = base64.b64decode(padded, altchars=b"-_").decode("utf-8", "ignore")
        except Exception:
            cred = userinfo
    else:
        padded = body + "=" * (-len(body) % 4)
        cred = base64.b64decode(padded, altchars=b"-_").decode("utf-8", "ignore")
        cred, hostport = cred.rsplit("@", 1)
    method, password = cred.split(":", 1)
    host, port = hostport.rsplit(":", 1)
    return {
        "name": name or f"ss-{host}:{port}",
        "type": "ss", "server": host, "port": int(port),
        "cipher": method.strip(), "password": password, "udp": True,
    }


def parse_trojan_uri(uri: str):
    u = urlparse(uri)
    if not (u.hostname and u.username):
        return None
    node = {
        "name": unquote(u.fragment) if u.fragment else f"trojan-{u.hostname}:{u.port or 443}",
        "type": "trojan", "server": u.hostname, "port": u.port or 443,
        "password": unquote(u.username), "udp": True,
    }
    for kv in (u.query or "").split("&"):
        k, _, v = kv.partition("=")
        if k == "sni" and v:
            node["sni"] = v
        elif k == "allowInsecure" and v.lower() in ("1", "true"):
            node["skip-cert-verify"] = True
    return node


# ---------- 5. 去重 ----------
def dedupe(proxies: list) -> list:
    seen, out = set(), []
    for p in proxies:
        key = (p.get("server"), p.get("port"), p.get("type"))
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    log(f"[DEDUPE] {len(proxies)} → {len(out)}")
    return out


# ---------- 6. TCP 测试 ----------
def tcp_alive(server: str, port: int) -> bool:
    try:
        with socket.create_connection((server, port), timeout=TCP_TIMEOUT):
            return True
    except Exception:
        return False


def filter_alive(proxies: list) -> list:
    alive = []
    with ThreadPoolExecutor(max_workers=TCP_WORKERS) as pool:
        futs = {pool.submit(tcp_alive, p["server"], p["port"]): p for p in proxies}
        for fut in as_completed(futs):
            p = futs[fut]
            if fut.result():
                alive.append(p)
            else:
                log(f"[TCP-FAIL] {p.get('name','?')} ({p['server']}:{p['port']})")
    log(f"[TCP] {len(proxies)} → {len(alive)} 存活")
    return alive


# ---------- 7. 输出 ----------
def write_clash_yaml(proxies: list) -> None:
    names = [p["name"] for p in proxies]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H:%M UTC")
    conf = {
        "mixed-port": 7890,
        "mode": "rule",
        "log-level": "info",
        "allow-lan": False,
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO"] + names},
            {"name": "AUTO",  "type": "url-test", "proxies": names,
             "url": "http://www.gstatic.com/generate_204", "interval": 300},
        ],
        "rules": [
            "DOMAIN-SUFFIX,cn,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,PROXY",
        ],
    }
    with open("clash.yaml", "w", encoding="utf-8") as f:
        f.write(f"# auto: update {now}\n")
        yaml.safe_dump(conf, f, allow_unicode=True, sort_keys=False)
    log(f"[WRITE] clash.yaml ({len(proxies)} 节点)")


def write_v2ray_txt(proxies: list) -> None:
    lines = []
    for p in proxies:
        if p["type"] == "vmess":
            obj = {"v": "2", "ps": p["name"], "add": p["server"],
                   "port": str(p["port"]), "id": p["uuid"],
                   "aid": str(p.get("alterId", 0)),
                   "net": p.get("network", "tcp"), "type": "none",
                   "host": (p.get("http-opts", {}).get("host") or [""])[0] if p.get("http-opts")
                           else (p.get("ws-opts", {}).get("headers", {}).get("Host", "") if p.get("ws-opts") else ""),
                   "path": p.get("ws-opts", {}).get("path", "/") if p.get("ws-opts")
                           else (p.get("http-opts", {}).get("path", [""])[0] if p.get("http-opts") else ""),
                   "tls": "tls" if p.get("tls") else "",
                   "scy": p.get("cipher", "auto")}
            raw = base64.b64encode(json.dumps(obj, ensure_ascii=False).encode()).decode()
            lines.append(f"vmess://{raw}")
        elif p["type"] == "ss":
            cred = base64.b64encode(f"{p['cipher']}:{p['password']}".encode()).decode()
            full = f"{cred}@{p['server']}:{p['port']}"
            lines.append(f"ss://{base64.b64encode(full.encode()).decode()}"
                         f"#{requests.utils.quote(p['name'])}")
        elif p["type"] == "trojan":
            lines.append(f"trojan://{p['password']}@{p['server']}:{p['port']}"
                         f"#{requests.utils.quote(p['name'])}")
    payload = "\n".join(lines)
    with open("v2ray.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode(payload.encode()).decode())
    log(f"[WRITE] v2ray.txt")


# ---------- 8. 主流程 ----------
def main() -> None:
    if not SUB_URL:
        log("[FAIL] 环境变量 MIAOMIAO_SUB_URL 未设置（请检查 GitHub Secrets）")
        raise SystemExit(1)

    log(f"[FETCH] {SUB_URL[:
