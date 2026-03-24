# Scan Scheduling — Implementation Notes

## Current Status
Scan scheduling is **not yet implemented** as a built-in feature.
Recurring scans are currently handled via **GitHub Actions cron jobs** (see `.github/workflows/upstream-watch.yml`).

## Proposed Architecture

### Option A: GitHub Actions (Recommended for now)
- Create a workflow `.github/workflows/scheduled-scan.yml`
- Use `workflow_dispatch` with target/profile inputs
- Schedule via `cron` trigger
- Results stored in DB, accessible via dashboard
- Pros: No infrastructure needed, already proven pattern
- Cons: Tied to GitHub, limited scheduling flexibility

### Option B: Built-in Scheduler (Future)
- New module: `src/vxis/core/scheduler.py`
- DB table: `scheduled_scans` (target, profile, cron_expr, enabled, last_run, next_run)
- Background worker using `asyncio` + `croniter` for cron expression parsing
- Dashboard UI: `/schedules` page with CRUD for scheduled scans
- CLI: `vxis schedule add/list/remove/enable/disable`
- Pros: Self-contained, no external dependencies
- Cons: Requires long-running process or daemon

### Option C: Celery / APScheduler
- Use APScheduler with async support
- Persistent job store in SQLite/PostgreSQL
- Integrates well with existing async codebase
- Pros: Battle-tested scheduling library
- Cons: Additional dependency

## Priority
Low — GitHub Actions covers immediate needs. Built-in scheduler should be considered when:
- Self-hosted deployments need standalone scheduling
- More granular control is required (per-client schedules, adaptive intervals)
- Dashboard-driven scan management is the primary workflow
