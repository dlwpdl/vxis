# `alembic/` — Database Migrations

SQLAlchemy + Alembic migration history for the VXIS local database (`vxis.db`). Stores scan results, finding persistence, growth loop state.

Phase A does NOT exercise the database — the v2 shim uses in-memory `finding_tools` state. Phase B episodic memory will start reading/writing via this DB.

```bash
# Run pending migrations
alembic upgrade head
```
