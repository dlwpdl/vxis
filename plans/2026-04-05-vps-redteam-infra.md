# VPS 레드팀 인프라 플랜
> 작성일: 2026-04-05

## 목표

C2(로컬 Windows)와 공격 트래픽 발원지를 물리적으로 분리하여 실제 레드팀 인프라 시뮬레이션.

**문제:** 현재 로컬 Docker는 bridge NAT으로 결국 C2 IP가 타겟에 노출됨.
**해결:** VPS에 Docker를 올리고 `DOCKER_HOST`로 원격 제어 — 코드 변경 없음.

---

## 목표 아키텍처

```
C2 (Windows)
  │  SSH 터널 — docker 명령만 전달 (제어 플레인)
  ▼
VPS (연구용)
  └── Docker daemon
        └── kali Container
              └── eth0 → VPS IP → Target   (데이터 플레인)
```

타겟이 보는 IP: VPS IP. C2 IP 노출 없음. nmap raw socket도 VPS IP로 나감.

---

## 구현 단계

### Step 1. VPS 프로비저닝
- OS: Ubuntu 22.04
- 국가: 타겟과 다른 국가 권장 (독일, 핀란드 등)

### Step 2. VPS Docker 설치
```bash
curl -fsSL https://get.docker.com | sh
usermod -aG docker $USER
```

### Step 3. C2 → VPS SSH 키 설정
```bash
# C2(Windows)에서
ssh-keygen -t ed25519 -f ~/.ssh/vxis_vps
ssh-copy-id -i ~/.ssh/vxis_vps.pub root@vps_ip
```

### Step 4. DOCKER_HOST 설정 (코드 변경 없음)
```bash
set DOCKER_HOST=ssh://root@vps_ip
python scripts/auto_pentest.py ghost://target.com
```

Docker CLI가 `DOCKER_HOST`를 자동으로 읽어 sandbox.py의 모든 docker 명령이 VPS에서 실행됨.

### Step 5. (선택) VPS 내부 추가 프록시
VPS IP도 숨기고 싶을 때:
```bash
# VPS에서 Tor 실행 후
VXIS_PROXY_POOL=socks5://127.0.0.1:9050 python scripts/auto_pentest.py ghost://target.com
# Container → Tor → Target (이중 홉)
```

---

## VPS 업체 선택

| 우선순위 | 업체 | 가격 | 이유 |
|---------|------|------|------|
| 1순위 (테스트) | **Kamatera** | 30일 무료 | 트라이얼로 테스트 후 버리기 |
| 2순위 (장기) | **RackNerd** | ~$1/월 (연납) | 프로모 딜 뜰 때 구매, 최고 가성비 |
| 3순위 (안정) | **Hetzner CAX11** | €3.29/월 | 항상 구매 가능, 빠른 프로비저닝 |

- **Kamatera**: 카드 등록 필요, 30일 청구 없음
- **RackNerd**: 프로모 딜은 재고 소진 시 구매 불가 — 보이면 바로 구매
- **Hetzner**: 언제든 가능, 연구용으로 가장 무난

---

## 주의사항

- VPS는 소모품 개념 — 탐지/블록 시 교체
- SSH 키는 VPS 전용으로 분리 관리
- Docker API를 TCP(2376)로 절대 열지 말 것 — SSH 터널만 사용
- 실제 교전 전 VPS IP가 타겟 ASN 블랙리스트에 없는지 확인

---

## 체크리스트

- [ ] VPS 프로비저닝
- [ ] Docker 설치
- [ ] SSH 키 설정
- [ ] DOCKER_HOST 연결 테스트 (`docker info` 로 확인)
- [ ] 스캔 실행 확인 (`python scripts/auto_pentest.py ghost://target.com`)
