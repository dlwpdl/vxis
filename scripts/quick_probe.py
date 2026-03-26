"""Quick probe script — 타깃 URL에 CPR Hands로 초기 탐색."""

import asyncio
import json
import sys

sys.path.insert(0, "src")

from vxis.interaction.hands import SessionManager
from vxis.interaction.xray import FlowAnalyzer


async def probe(target: str) -> None:
    print(f"\n{'='*60}")
    print(f"  VXIS CPR Quick Probe: {target}")
    print(f"{'='*60}\n")

    mgr = SessionManager()
    session = await mgr.get_session(target)

    # 1. 초기 요청
    print("[1] Initial Request...")
    resp = await session.get("/")
    print(f"    Status: {resp.status}")
    print(f"    Content-Type: {resp.content_type}")
    print(f"    Body length: {len(resp.text)} chars")

    # 2. 핑거프린트
    print("\n[2] Fingerprint...")
    fp = session.get_fingerprint()
    print(f"    Tech Stack: {fp.get('tech_stack', [])}")
    print(f"    Server: {fp.get('server', 'N/A')}")
    print(f"    WAF Detected: {fp.get('waf_detected', False)}")
    print(f"    CSRF: {fp.get('has_csrf', False)}")

    # 3. 보안 헤더
    print("\n[3] Security Headers...")
    headers = resp.headers
    sec_headers = {
        "Strict-Transport-Security": headers.get("strict-transport-security", "MISSING"),
        "X-Frame-Options": headers.get("x-frame-options", "MISSING"),
        "X-Content-Type-Options": headers.get("x-content-type-options", "MISSING"),
        "Content-Security-Policy": headers.get("content-security-policy", "MISSING")[:80],
        "X-XSS-Protection": headers.get("x-xss-protection", "MISSING"),
        "Referrer-Policy": headers.get("referrer-policy", "MISSING"),
        "Permissions-Policy": headers.get("permissions-policy", "MISSING")[:80],
    }
    for h, v in sec_headers.items():
        status = "OK" if v != "MISSING" else "MISSING"
        print(f"    [{status:7s}] {h}: {v}")

    # 4. 폼 탐색
    print("\n[4] Forms Found...")
    if resp.forms:
        for f in resp.forms:
            print(f"    Form: action={f.action}, method={f.method}")
            print(f"      Fields: {[fd['name'] for fd in f.fields]}")
            print(f"      CSRF: {f.has_csrf}")
    else:
        print("    No forms found on /")

    # 5. 링크 탐색
    print("\n[5] Links Found...")
    if resp.links:
        for link in resp.links[:30]:
            print(f"    {link}")
        if len(resp.links) > 30:
            print(f"    ... and {len(resp.links) - 30} more")
    else:
        print("    No links found on /")

    # 6. 에러 패턴
    print("\n[6] Error Patterns / Info Leaks...")
    if resp.error_patterns:
        for p in resp.error_patterns:
            print(f"    [!] {p}")
    else:
        print("    None detected")

    # 7. 크롤링 (depth=1)
    print("\n[7] Crawling (depth=1)...")
    try:
        endpoints = await session.crawl_links("/", depth=1)
        print(f"    Discovered {len(endpoints)} endpoints:")
        for ep in sorted(endpoints)[:40]:
            print(f"    {ep}")
        if len(endpoints) > 40:
            print(f"    ... and {len(endpoints) - 40} more")
    except Exception as e:
        print(f"    Crawl error: {e}")

    # X-Ray 패시브 분석
    print("\n[8] Passive Analysis (X-Ray)...")
    analyzer = FlowAnalyzer()
    flow = analyzer.create_flow_from_request(
        method="GET",
        url=f"{target}/",
        headers=dict(resp.response.request.headers),
        body="",
    )
    analyzer.update_flow_response(
        flow,
        status_code=resp.status,
        headers=dict(resp.headers),
        body=resp.text[:10000],
    )
    analyzer.add_flow(flow)
    summary = analyzer.get_summary()
    if summary.vulnerabilities:
        for v in summary.vulnerabilities:
            print(f"    [!] {v}")
    if summary.secrets_found:
        for s in summary.secrets_found:
            print(f"    [SECRET] {s}")
    if summary.auth_tokens_found:
        for t in summary.auth_tokens_found:
            print(f"    [TOKEN] {t}")
    if not (summary.vulnerabilities or summary.secrets_found or summary.auth_tokens_found):
        print("    No passive findings from initial request")

    await mgr.close_all()

    print(f"\n{'='*60}")
    print("  Probe Complete")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://kinetics-dev.protopie.works"
    asyncio.run(probe(target))
