---
name: ProtoPie Studio macOS Desktop Validation
type: benchmark
status: active
when_to_read: macOS desktop pipeline 의 첫 third-party 검증 결과 / signed app 동작 확인 / entitlement audit 가 L2 finding 까지 끌어올린 사례 / VXIS 0.2.0 desktop baseline
updated: 2026-04-23
sources:
  - ../reports/protopie.html
  - ../reports/protopie.score.json
  - ../logs/scan_20260423_100857.log
related:
  - entities/skills/test_ipc_injection.md
  - entities/skills/test_binary_protections.md
  - concepts/cross_surface_synthesis.md
  - decisions/010_universal_pentest_plan_refresh.md
---
# ProtoPie Studio macOS Desktop Validation

## 핵심 사실
| 항목 | 값 |
|---|---|
| 일자 | 2026-04-23 |
| 타겟 | `/Applications/ProtoPie.app` (서명: Developer ID Application: Studio XID, Inc, Hardened Runtime ON) |
| VXIS 버전 | 0.2.0 |
| Total / Grade | **414.09 / C** |
| 5 차원 | VC = 120 · ER = 94.09 · CI = 0 · FP = 100 · CO = 100 |
| Findings | 22 (L1: 21 × LC_LOAD_WEAK_DYLIB + L2: 1 × `com.apple.security.cs.allow-jit` entitlement) |
| Iterations | 50 (max), 약 170 초 (10:08:57 → 10:11:47) |
| Brain 결정 / LLM 호출 | 50 / 57 (peak context 104,215 bytes) |
| 리포트 파일 | `reports/protopie.html` (208 KB), `reports/protopie.score.json` |

## TL;DR
macOS desktop pipeline 이 third-party signed app 에서 처음으로 end-to-end 동작함을 입증한 검증. 서명·Hardened Runtime 이 켜진 ProtoPie.app 에서도 dylib weak-link 21 건 + JIT 허용 entitlement 1 건 (L2) 을 채굴, 총 414.09 (C grade). VXIS 0.2.0 의 desktop baseline 으로 박제.

## What
2026-04-23 phase-Q11 직후, scan_loop 의 0-finding finish_scan reject (Q11) + `_real_skills_completed` VC 매핑 (Q10) 을 검증하기 위한 stress test. ProtoPie Studio 는 (a) Apple Developer ID 정식 서명, (b) Hardened Runtime 활성, (c) Electron 기반 — macOS desktop pipeline 이 가장 흔한 production-grade 앱에서 동작하는지 보는 게 목적.

## How
```bash
python -m vxis.cli scan --target /Applications/ProtoPie.app --mode desktop
# 50 iter / 170 sec / log: logs/scan_20260423_100857.log
```
실행된 macOS skills (iter ≥ 25 sweep): `test_dylib_hijack`, `test_local_storage_secrets`, `test_signature_audit`, `test_entitlement_audit`, `test_electron_misconfig`, `test_deeplink_abuse`. 22 findings 모두 `_real_skills_completed` set 으로 들어가 VC 크레딧 받음 (Q10 의도대로).

## Result Breakdown
- **VC = 120/250 (48%)**: 18/18 desktop vector attempt (만점 attempt), 0/18 found (vulnerable=False 가 다수). vector 종류: information_disclosure 1 + misconfiguration 16 + recon 1.
- **ER = 94.09/300 (31%)**: L0=0, L1=21, L2=1, L3=0, L4=0. Crown jewel 미달성, 그러나 entitlement audit 가 단일 finding 을 L2 로 끌어올림.
- **CI = 0/150**: 22 findings → 7 chains 목표 (`max(3, 22//3)`) 이지만 actual chains = 0. dylib hijack 21 건이 모두 동일 패턴 (`@rpath/Electron Framework`) 이라 chain 그래프가 의미 없게 떨어짐 — 향후 cross-surface chain 으로 발전 필요.
- **FP = 100/200**: judgment 없음 (`measurement_valid: false`) → Bayesian 중립 100.
- **CO = 100/100**: phase 완료율 만점.

## 의미
- **macOS desktop pipeline 의 first third-party 검증** — 그동안 Calculator.app smoke 로만 검증됐는데, signed + Hardened Runtime + Electron 조합에서도 finding 이 나옴.
- **Entitlement audit 의 가치 입증** — 21 건의 L1 dylib finding 만이라면 ER 점수가 낮았을 텐데, `com.apple.security.cs.allow-jit` 한 건이 L2 로 잡혀 ER 의 actual_points 가 21×3 + 1×6 = 69 까지 도달.
- **Q10 / Q11 정상 동작** — `_real_skills_completed` 가 18 vector attempted 로 잡혀 VC=120, finish_scan 이 0-finding gate 에 걸리지 않음 (실제 22 findings 발생).
- **Next**: chain intelligence (CI=0) 가 약점 — dylib finding 21 개가 같은 root 라 dedup 후 chain 1개로 압축할지, surface-cross chain (Electron framework + remote update endpoint) 으로 확장할지 결정 필요.
