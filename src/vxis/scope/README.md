# `src/vxis/scope/` — Scope Enforcement Layer

Allow/deny URL pattern matching to prevent the Brain from hitting out-of-scope targets (e.g. third-party CDNs, login providers).

Integrated at the Hands layer (`interaction/hands.py`) so any in-process HTTP request is checked. The Brain's sandbox tools (`shell_exec`, `python_exec`) currently bypass this because they use their own HTTP clients — Phase C will add sandbox-side egress filtering.
