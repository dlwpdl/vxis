# `src/vxis/scheduler/` — Continuous Monitoring Scheduler

Cron-like scheduler for recurring scans. Triggers `vxis scan` on schedule against a fleet of registered targets, stores results in the local DB, sends webhook notifications via `integrations/`.

Phase A does not exercise this module — benchmarks are single on-demand scans.
