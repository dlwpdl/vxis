---
name: P7 Hardware
type: pipeline
status: active
when_to_read: 하드웨어·물리 계층 공격 / DMA·콜드부트·사이드채널 에이전트 / 모바일·IoT 펌웨어
updated: 2026-04-16
sources:
  - ../../../src/vxis/agent/agents/dma_attack_agent.py
  - ../../../src/vxis/agent/agents/cold_boot_memory_agent.py
  - ../../../src/vxis/agent/agents/side_channel_agent.py
  - ../../../src/vxis/agent/agents/iot_firmware_agent.py
related:
  - ./P5_special.md
  - ./P8_synthesis.md
code_anchors:
  - src/vxis/agent/agents/dma_attack_agent.py
  - src/vxis/agent/agents/side_channel_agent.py
  - src/vxis/agent/agents/iot_firmware_agent.py
---
# P7 — Hardware

## 핵심 사실
| 항목 | 값 |
|---|---|
| Group | 4 Exploitation |
| 앞 단계 | P5 Special |
| 뒤 단계 | P8 Synthesis |
| 역할 | 하드웨어·물리 계층 공격 에이전트 집합 |
| 대상 | DMA, 콜드부트, 사이드채널, IoT 펌웨어, 블루투스, ICS/SCADA |
| 특성 | 물리 접근·전파·타이밍 등 SW-only 로 감지 불가 |

## TL;DR
SW 공격(P5)만으론 커버 못 하는 하드웨어·물리 계층 공격. DMA attack, cold boot memory dump, power analysis side channel, IoT 펌웨어 덤프, 블루투스/BLE 프로토콜, 산업 제어 시스템(ICS/SCADA) 에이전트가 이 단계에 속함.

## Stage
Exploitation — P5 와 병렬. 타겟 범위에 하드웨어 요소가 있을 때만 활성화.

## Inputs-Outputs
- Input: 물리 디바이스 핸들, 펌웨어 이미지, 센서 데이터.
- Output: `Finding` (하드웨어 취약점, pwn chain).

## Triggers
- MissionConfig 에 hardware scope 포함 시 Director 가 자동 스폰.
- 특정 에이전트(iot_firmware_agent 등) 가설 발생 시.

## Related Pipelines
- [P5 Special](./P5_special.md) — 앞 단계 (SW exploitation)
- [P8 Synthesis](./P8_synthesis.md) — 뒤 단계 (HW+SW 체인 합성)
