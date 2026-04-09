# `src/vxis/knowledge/` — Vulnerability Knowledge Base

Compiled attack patterns, payload corpora, CVE signatures, and a knowledge store for recording "what worked" across scans.

Legacy pipeline used this for pattern matching + compiled payload selection. Phase A's Brain-First loop currently does not consume the knowledge store — Phase B's episodic memory will build on top of this module.

Key types: `KnowledgeStore`, `ExecutionRecord`, compiled pattern loaders.
