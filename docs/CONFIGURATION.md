# VXIS Configuration Guide — 설정해야 할 모든 것

## 필수 설정 (바로 동작에 필요)

### 1. LLM (AI 두뇌) — 최소 1개

| 방법 | 환경변수 | 비용 | 설정 |
|------|---------|------|------|
| **Claude Code 구독** | (자동 감지) | $0 | `claude` CLI 설치되어 있으면 자동 |
| **Gemini CLI 구독** | (자동 감지) | $0 | `gemini` CLI 설치되어 있으면 자동 |
| **Together.ai API** | `TOGETHER_API_KEY` | $0.50/M | [together.ai](https://api.together.ai/settings) |
| **Anthropic API** | `ANTHROPIC_API_KEY` | $3/M | [console.anthropic.com](https://console.anthropic.com) |
| **Google Gemini** | `GOOGLE_API_KEY` | 무료 tier | [aistudio.google.com](https://aistudio.google.com) |
| **OpenAI** | `OPENAI_API_KEY` | $0.15/M | [platform.openai.com](https://platform.openai.com) |

```bash
# 권장: Together.ai (저렴 + 다양한 모델)
export TOGETHER_API_KEY="..."

# 또는 .env 파일
echo 'TOGETHER_API_KEY=...' >> .env
```

### 2. Telegram 알림

```bash
# 1. @BotFather에서 봇 생성 → 토큰 받기
# 2. 봇에게 /start 보낸 후 Chat ID 확인
#    https://api.telegram.org/bot<TOKEN>/getUpdates

export TELEGRAM_BOT_TOKEN="1234567890:AABBC..."
export TELEGRAM_CHAT_ID="123456789"
```

**GitHub Secrets에도 추가:** Settings → Secrets → `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`

### 3. 보안 도구 설치

```bash
# Go 설치 (httpx, nuclei 등에 필요)
brew install go
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zshrc

# 핵심 도구
brew install nmap nuclei testssl trufflehog gitleaks

# Go 바이너리
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Python 도구 (pipx로 격리 설치)
pipx install sslyze --python python3.12
pipx install checkdmarc --python python3.12

# 전체 도구 설치 (VXIS CLI)
.venv/bin/python -m vxis.cli.main setup
```

---

## 선택 설정 (기능별)

### Upstream Watcher (오픈소스 감시)

| 항목 | 환경변수 | 위치 |
|------|---------|------|
| LLM Provider | `UPSTREAM_LLM_PROVIDER` | GitHub Vars |
| LLM Model | `UPSTREAM_LLM_MODEL` | GitHub Vars |
| Together API | `TOGETHER_API_KEY` | GitHub Secrets |
| Telegram | `TELEGRAM_BOT_TOKEN` | GitHub Secrets |

### CVE Watch Daemon (취약점 감시)

| 항목 | 환경변수 | 비용 |
|------|---------|------|
| NVD API (선택) | `NVD_API_KEY` | 무료 (속도 향상) |
| GitHub Token | `GITHUB_TOKEN` | 자동 제공 |

```bash
# NVD API 키 (선택, 없어도 동작하지만 느림)
# https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY="..."
```

### Intelligence Watchers (11개)

| 워처 | 필요한 키 | 비용 |
|------|----------|------|
| Dark Web Intel | `INTELX_API_KEY` | 무료 tier |
| Leaked Credential | `HIBP_API_KEY` | $3.50/월 |
| Ransomware Gang | (없음) | 무료 |
| Exploit Market | `GITHUB_TOKEN` | 무료 |
| Cert Transparency | (없음) | 무료 |
| Supply Chain | (없음) | 무료 |
| Infra Drift | (없음, nmap 필요) | 무료 |
| Brand Impersonation | (없음, dnstwist 필요) | 무료 |
| Threat Actor | `OTX_API_KEY` (선택) | 무료 |

```bash
# IntelligenceX (다크웹 검색)
# https://intelx.io/account?tab=developer
export INTELX_API_KEY="..."

# Have I Been Pwned
# https://haveibeenpwned.com/API/Key
export HIBP_API_KEY="..."

# AlienVault OTX (선택)
# https://otx.alienvault.com/api
export OTX_API_KEY="..."
```

### Shodan (외부 인텔리전스)

```bash
pip install shodan
shodan init <API_KEY>
# 무료 계정은 제한적, $49 평생 라이선스 권장
```

### Docker (샌드박스 + 디지털 트윈)

```bash
# Docker Desktop 설치
# https://www.docker.com/products/docker-desktop/

# 확인
docker info
```

### AWS Canary Token (허니팟 추적)

```bash
# 1. AWS IAM에서 권한 없는 사용자 생성
# 2. Access Key 발급 (이 키가 canary)
# 3. CloudTrail 알림 설정
#    → 이 키로 API 호출 시 즉시 SNS → Telegram
```

---

## GitHub Actions Secrets 전체 목록

| Secret | 용도 | 필수 |
|--------|------|------|
| `TOGETHER_API_KEY` | LLM 분석 | ✅ |
| `TELEGRAM_BOT_TOKEN` | 알림 | ✅ |
| `TELEGRAM_CHAT_ID` | 알림 | ✅ |
| `ANTHROPIC_API_KEY` | LLM fallback | 선택 |
| `GOOGLE_API_KEY` | LLM fallback | 선택 |
| `OPENAI_API_KEY` | LLM fallback | 선택 |
| `NVD_API_KEY` | CVE 조회 가속 | 선택 |
| `INTELX_API_KEY` | 다크웹 검색 | 선택 |
| `HIBP_API_KEY` | 유출 확인 | 선택 |
| `OTX_API_KEY` | 위협 인텔 | 선택 |
| `SHODAN_API_KEY` | 인터넷 검색 | 선택 |

### GitHub Variables

| Variable | 값 | 기본값 |
|----------|---|--------|
| `UPSTREAM_LLM_PROVIDER` | together/anthropic/google | together |
| `UPSTREAM_LLM_MODEL` | 모델 ID 또는 shortcut | moonshotai/Kimi-K2.5 |

---

## 실행 방법

```bash
# 인터랙티브 CLI
.venv/bin/python -m vxis.cli.main

# AI 에이전트 자율 스캔
vxis → 🧠 AI 자율 스캔 → 모델 선택 → 타겟 입력

# 대시보드
.venv/bin/python -m vxis.cli.main dashboard

# CVE Watch (독립 실행)
python -m vxis.watchers

# 전체 워처 (11개 병렬)
python -c "
import asyncio
from vxis.watchers.base import WatcherOrchestrator
asyncio.run(WatcherOrchestrator().run_all_once())
"

# MCP 서버 (Claude Code 연동)
claude mcp add vxis .venv/bin/python -m vxis.mcp_server
```

---

## 월 운영 비용 추정

| 항목 | 비용 |
|------|------|
| LLM (CLI 구독) | $0 |
| GitHub Actions | $0 |
| Telegram | $0 |
| NVD/OSV/CISA | $0 |
| HIBP (선택) | $3.50 |
| IntelX (선택) | $0 (무료 tier) |
| **총** | **$0 ~ $3.50/월** |
