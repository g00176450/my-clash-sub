def fetch_daily_url(s) -> str:
    r = s.get(UI_PATH, timeout=TIMEOUT)
    r.raise_for_status()

    # ★ 关键修复：还原 JSON/HTML 中的转义斜杠
    html = (r.text
            .replace('\\/', '/')
            .replace('&#x2F;', '/')
            .replace('%2F', '/'))

    # 调试：列出页面里命中的所有订阅链接
    found = re.findall(
        r'/v1/sub/(vmess|hysteria2?|ssr)/(\d+)/([A-Za-z0-9\-_]{10,})', html)
    print(f"[DEBUG] 页面命中 {len(found)} 条订阅链接:")
    for proto, ts, tok in found:
        print(f"[DEBUG]   {proto:9s} ts={ts} token={tok[:8]}...")

    # 优先 vmess（浏览器实测该端点返回 Clash YAML）
    m = re.search(r'/v1/sub/vmess/(\d+)/([A-Za-z0-9\-_]{10,})', html)
    if m:
        url = f"{BASE_URL}/v1/sub/vmess/{m.group(1)}/{m.group(2)}"
        print(f"[OK] 选用 vmess 订阅: {url}")
        return url

    # 兜底：任意协议先拿到再说
    m2 = re.search(r'/v1/sub/(?:hysteria2?|ssr)/(\d+)/([A-Za-z0-9\-_]{10,})', html)
    if m2:
        proto = m2.group(0).split('/')[3]
        print(f"[WARN] 未找到 vmess，退回 {proto} 订阅")
        return f"{BASE_URL}{m2.group(0)}"

    # 仍然找不到：打印页面片段供人工排查
    print("[DEBUG] ===== Page HEAD (前 2000 字符) =====")
    print(html[:2000])
    raise RuntimeError("未匹配到订阅链接：请查看上方 DEBUG 输出")
