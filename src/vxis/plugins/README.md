# `src/vxis/plugins/` — Scanner Plugin System

Plugin registry for external scanner integrations (nuclei templates, custom nuclei packs, semgrep rules, gitleaks configs). Loaded at startup by `vxis.registry`.

Phase A's Brain invokes external scanners via `shell_exec` directly — plugin registration is not used by the loop path. Legacy pipeline phases still import from here.
