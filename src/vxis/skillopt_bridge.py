from __future__ import annotations

import json
import os
import random
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


@dataclass
class SkillOptExportResult:
    out_dir: str
    total: int
    train: int
    val: int
    test: int
    config_path: str
    seed_skill_path: str


@dataclass
class OptimizedSkill:
    name: str
    path: str
    surface: str = "web"
    families: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    triggers: list[str] = field(default_factory=list)
    source: str = ""
    active: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OptimizedSkill":
        return cls(
            name=str(data.get("name") or ""),
            path=str(data.get("path") or ""),
            surface=str(data.get("surface") or "web"),
            families=[str(x) for x in data.get("families", []) or []],
            roles=[str(x) for x in data.get("roles", []) or []],
            triggers=[str(x) for x in data.get("triggers", []) or []],
            source=str(data.get("source") or ""),
            active=bool(data.get("active", True)),
        )


def skillopt_home() -> Path:
    return Path(os.environ.get("VXIS_SKILLOPT_HOME", Path.home() / ".vxis" / "skillopt")).expanduser()


def default_split_dir(name: str) -> Path:
    return skillopt_home() / "splits" / _safe_name(name)


def default_run_dir(name: str) -> Path:
    return skillopt_home() / "runs" / _safe_name(name)


def skillopt_checkout() -> Path:
    return Path(
        os.environ.get("VXIS_SKILLOPT_CHECKOUT", "/Users/eliot/Desktop/gitt/SkillOpt")
    ).expanduser()


def export_searchqa_split(
    case_file: str | Path,
    out_dir: str | Path,
    *,
    train_ratio: float = 0.6,
    val_ratio: float = 0.2,
    seed: int = 42,
) -> SkillOptExportResult:
    records = [_normalize_case(record, index=i) for i, record in enumerate(_load_records(case_file), 1)]
    if not records:
        raise ValueError(f"no cases found in {case_file}")

    rng = random.Random(seed)
    rng.shuffle(records)
    train, val, test = _split_records(records, train_ratio=train_ratio, val_ratio=val_ratio)

    out = Path(out_dir)
    for split_name, items in (("train", train), ("val", val), ("test", test)):
        split_dir = out / split_name
        split_dir.mkdir(parents=True, exist_ok=True)
        (split_dir / "items.json").write_text(
            json.dumps(items, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    seed_skill = out / "vxis_seed_skill.md"
    seed_skill.write_text(DEFAULT_VXIS_SKILLOPT_SEED, encoding="utf-8")
    config = out / "vxis_searchqa_config.yaml"
    config.write_text(_render_searchqa_config(out, seed_skill), encoding="utf-8")
    (out / "README.md").write_text(_render_export_readme(out, config), encoding="utf-8")

    return SkillOptExportResult(
        out_dir=str(out),
        total=len(records),
        train=len(train),
        val=len(val),
        test=len(test),
        config_path=str(config),
        seed_skill_path=str(seed_skill),
    )


def import_optimized_skill(
    skill_path: str | Path,
    *,
    name: str,
    surface: str = "web",
    families: Iterable[str] = (),
    roles: Iterable[str] = (),
    triggers: Iterable[str] = (),
    active: bool = True,
) -> OptimizedSkill:
    source = Path(skill_path)
    if not source.exists():
        raise FileNotFoundError(source)
    clean_name = _safe_name(name)
    if not clean_name:
        raise ValueError("optimized skill name is empty")
    home = skillopt_home()
    skill_dir = home / "optimized"
    skill_dir.mkdir(parents=True, exist_ok=True)
    dest = skill_dir / f"{clean_name}.md"
    dest.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    entry = OptimizedSkill(
        name=clean_name,
        path=str(dest),
        surface=str(surface or "web"),
        families=_clean_list(families),
        roles=_clean_list(roles),
        triggers=_clean_list(triggers),
        source=str(source),
        active=active,
    )
    index = {item.name: item for item in list_optimized_skills()}
    index[entry.name] = entry
    _write_index(index.values())
    return entry


def set_optimized_skill_active(name: str, active: bool) -> OptimizedSkill:
    clean_name = _safe_name(name)
    index = {item.name: item for item in list_optimized_skills()}
    if clean_name not in index:
        raise KeyError(name)
    entry = index[clean_name]
    entry.active = active
    _write_index(index.values())
    return entry


def latest_best_skill(run_dir: str | Path) -> Path:
    root = Path(run_dir)
    direct = root / "best_skill.md"
    if direct.exists():
        return direct
    candidates = sorted(root.glob("**/best_skill.md"), key=lambda path: path.stat().st_mtime)
    if not candidates:
        raise FileNotFoundError(f"best_skill.md not found under {root}")
    return candidates[-1]


def build_train_command(
    name: str,
    *,
    config_path: str | Path | None = None,
    checkout: str | Path | None = None,
    out_root: str | Path | None = None,
    epochs: int | None = None,
    workers: int | None = None,
) -> list[str]:
    clean_name = _safe_name(name)
    config = Path(config_path) if config_path is not None else default_split_dir(clean_name) / "vxis_searchqa_config.yaml"
    command = ["python", "scripts/train.py", "--config", str(config)]
    cfg_options: list[str] = []
    if out_root is not None:
        cfg_options.append(f"env.out_root={out_root}")
    else:
        cfg_options.append(f"env.out_root={default_run_dir(clean_name)}")
    if epochs is not None:
        cfg_options.append(f"train.num_epochs={int(epochs)}")
    if workers is not None:
        cfg_options.append(f"env.workers={int(workers)}")
    if cfg_options:
        command.extend(["--cfg-options", *cfg_options])
    return command


def run_skillopt_train(
    name: str,
    *,
    config_path: str | Path | None = None,
    checkout: str | Path | None = None,
    out_root: str | Path | None = None,
    epochs: int | None = None,
    workers: int | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    cwd = Path(checkout) if checkout is not None else skillopt_checkout()
    command = build_train_command(
        name,
        config_path=config_path,
        checkout=cwd,
        out_root=out_root,
        epochs=epochs,
        workers=workers,
    )
    result: dict[str, Any] = {"cwd": str(cwd), "command": command, "dry_run": dry_run}
    if dry_run:
        return result
    completed = subprocess.run(command, cwd=cwd, check=False, text=True)  # noqa: S603
    result["returncode"] = completed.returncode
    if completed.returncode != 0:
        raise RuntimeError(f"SkillOpt train failed with exit code {completed.returncode}")
    return result


def list_optimized_skills() -> list[OptimizedSkill]:
    index_path = _index_path()
    if not index_path.exists():
        return []
    try:
        raw = json.loads(index_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    entries = raw.get("skills", []) if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        return []
    return [item for item in (OptimizedSkill.from_dict(e) for e in entries if isinstance(e, dict)) if item.name]


def load_optimized_skill(name: str) -> tuple[OptimizedSkill, str]:
    for entry in list_optimized_skills():
        if entry.name == name:
            path = Path(entry.path)
            return entry, path.read_text(encoding="utf-8")
    raise KeyError(name)


def render_optimized_skill_context(
    *,
    task: str,
    role: str = "director",
    explicit_skills: Iterable[str] | None = None,
    target_kind: str = "web",
    max_chars: int = 1_400,
) -> str:
    if os.environ.get("VXIS_SKILLOPT_ENABLED", "1").strip().lower() in {"0", "false", "no", "off"}:
        return ""
    entries = _select_optimized_skills(
        task=task,
        role=role,
        explicit_skills=explicit_skills or (),
        target_kind=target_kind,
    )
    if not entries:
        return ""
    lines = [
        "Optimized SkillOpt guidance. Treat this as learned strategy memory, not proof.",
    ]
    for index, entry in enumerate(entries, 1):
        try:
            content = Path(entry.path).read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if not content:
            continue
        lines.extend(
            [
                f"{index}. {entry.name} [{', '.join(entry.families) or entry.surface}]",
                _indent(_strip_frontmatter(content), "   "),
            ]
        )
    rendered = "\n".join(lines).strip()
    if len(rendered) <= max_chars:
        return rendered
    return rendered[: max(0, max_chars - 24)].rstrip() + "\n...truncated..."


def _load_records(path: str | Path) -> list[dict[str, Any]]:
    raw = Path(path).read_text(encoding="utf-8").strip()
    if not raw:
        return []
    try:
        decoded = json.loads(raw)
        if isinstance(decoded, list):
            return [item for item in decoded if isinstance(item, dict)]
        if isinstance(decoded, dict):
            data = decoded.get("data") or decoded.get("items") or decoded.get("cases")
            if isinstance(data, list):
                return [item for item in data if isinstance(item, dict)]
            return [decoded]
    except json.JSONDecodeError:
        pass
    rows: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if line.strip():
            item = json.loads(line)
            if isinstance(item, dict):
                rows.append(item)
    return rows


def _normalize_case(record: dict[str, Any], *, index: int) -> dict[str, Any]:
    answers = record.get("answers") or record.get("expected_answers") or record.get("expected")
    if isinstance(answers, str):
        answers = [answers]
    if not isinstance(answers, list):
        action = record.get("expected_action") or record.get("label") or record.get("next_action")
        answers = [str(action)] if action else []
    answers = [str(answer).strip() for answer in answers if str(answer).strip()]
    if not answers:
        raise ValueError(f"case {record.get('id') or index} is missing expected answer/action")

    question = str(record.get("question") or "").strip()
    if not question:
        question = (
            "Given the VXIS scan context, choose the best next action label. "
            "Return only the label inside <answer>...</answer>."
        )
    context = _case_context(record)
    return {
        "id": str(record.get("id") or f"vxis_case_{index:04d}"),
        "question": question,
        "context": context,
        "answers": answers,
        "task_type": str(record.get("task_type") or record.get("family") or "vxis_next_action"),
    }


def _case_context(record: dict[str, Any]) -> str:
    sections: list[str] = []
    for key, title in (
        ("target", "Target"),
        ("profile", "Profile"),
        ("surface", "Surface"),
        ("finding_family", "Finding Family"),
        ("available_actions", "Available Actions"),
        ("state", "State"),
        ("evidence", "Evidence"),
        ("trajectory", "Trajectory"),
        ("transcript", "Transcript"),
        ("notes", "Notes"),
    ):
        if key in record and record[key] not in (None, ""):
            sections.append(f"[DOC] {title}\n{_stringify(record[key])}")
    if not sections:
        sections.append(f"[DOC] VXIS Case\n{_stringify({k: v for k, v in record.items() if k != 'answers'})}")
    return "\n\n".join(sections)


def _split_records(
    records: list[dict[str, Any]],
    *,
    train_ratio: float,
    val_ratio: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    total = len(records)
    if total == 1:
        return records, [], []
    train_count = max(1, min(total, int(round(total * train_ratio))))
    val_count = max(0, int(round(total * val_ratio)))
    if train_count + val_count > total:
        val_count = max(0, total - train_count)
    if total >= 3 and total - train_count - val_count == 0:
        if val_count > 0:
            val_count -= 1
        elif train_count > 1:
            train_count -= 1
    return (
        records[:train_count],
        records[train_count : train_count + val_count],
        records[train_count + val_count :],
    )


def _render_searchqa_config(out_dir: Path, seed_skill: Path) -> str:
    return (
        "_base_: /Users/eliot/Desktop/gitt/SkillOpt/configs/searchqa/default.yaml\n\n"
        "env:\n"
        "  name: searchqa\n"
        f"  skill_init: {seed_skill}\n"
        "  split_mode: split_dir\n"
        f"  split_dir: {out_dir}\n"
        "  data_path: \"\"\n"
        "  split_output_dir: \"\"\n"
        "  max_turns: 1\n"
        "  max_completion_tokens: 4096\n"
        "  workers: 4\n"
        "  limit: 0\n\n"
        "train:\n"
        "  train_size: 40\n"
        "  batch_size: 8\n"
        "  num_epochs: 2\n\n"
        "gradient:\n"
        "  minibatch_size: 4\n"
        "  merge_batch_size: 4\n\n"
        "evaluation:\n"
        "  sel_env_num: 0\n"
        "  test_env_num: 0\n"
    )


def _render_export_readme(out_dir: Path, config: Path) -> str:
    return (
        "# VXIS SkillOpt Export\n\n"
        "This directory is a SkillOpt `searchqa`-compatible split generated from VXIS cases.\n\n"
        "Run from the local SkillOpt checkout:\n\n"
        "```bash\n"
        "cd /Users/eliot/Desktop/gitt/SkillOpt\n"
        f"python scripts/train.py --config {config}\n"
        "```\n\n"
        "After training, import the generated `best_skill.md` into VXIS:\n\n"
        "```bash\n"
        "vxis skillopt import outputs/<run>/best_skill.md --name axis2 --families access_control,chain --roles director,post_exploit_worker\n"
        "```\n"
        "\nOr use the VXIS helper:\n\n"
        "```bash\n"
        "vxis skillopt train <name> --config "
        f"{config}\n"
        "vxis skillopt apply <name> --run-dir .vxis/skillopt/runs/<name>\n"
        "```\n"
    )


def _select_optimized_skills(
    *,
    task: str,
    role: str,
    explicit_skills: Iterable[str],
    target_kind: str,
) -> list[OptimizedSkill]:
    text = f"{task} {role}".lower()
    explicit = {str(item).strip().lower() for item in explicit_skills if str(item).strip()}
    kind = str(target_kind or "web").lower()
    scored: list[tuple[int, str, OptimizedSkill]] = []
    for entry in list_optimized_skills():
        if not entry.active:
            continue
        score = 0
        if entry.surface and entry.surface.lower() not in {kind, "all", "*"}:
            continue
        if entry.name.lower() in explicit:
            score += 1000
        if role.lower() in {r.lower() for r in entry.roles}:
            score += 60
        for token in entry.families + entry.triggers:
            clean = token.lower().replace("_", " ")
            if clean and clean in text:
                score += 30
        if score > 0 or not entry.families and not entry.triggers:
            scored.append((score, entry.name, entry))
    return [entry for _score, _name, entry in sorted(scored, reverse=True)[:3]]


def _write_index(entries: Iterable[OptimizedSkill]) -> None:
    path = _index_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"skills": [asdict(entry) for entry in sorted(entries, key=lambda item: item.name)]}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _index_path() -> Path:
    return skillopt_home() / "optimized" / "index.json"


def _clean_list(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        for item in str(value or "").split(","):
            clean = item.strip()
            if clean:
                out.append(clean)
    return out


def _safe_name(value: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "_" for ch in str(value or "")).strip("_")


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def _strip_frontmatter(content: str) -> str:
    text = content.strip()
    if not text.startswith("---"):
        return text
    parts = text.split("---", 2)
    if len(parts) == 3:
        return parts[2].strip()
    return text


def _indent(text: str, prefix: str) -> str:
    return "\n".join(prefix + line if line.strip() else line for line in text.splitlines())


DEFAULT_VXIS_SKILLOPT_SEED = """# VXIS Next-Action Strategy

You are optimizing VXIS agent decisions, not writing findings directly.

## Output Rule
Return the selected next-action label inside `<answer>...</answer>`.

## General Strategy
- Prefer actions that close a missing proof gap over broad repeated recon.
- For access-control cases, establish two identities, enumerate owned objects, then test cross-identity access.
- For SSRF cases, distinguish client-side reflection from server-side fetch before escalating to cloud impact proof.
- For business-logic cases, replay a normal captured flow first, then mutate one business field at a time.
- If the same reusable skill already failed on the same surface, pivot to a fresh surface or a lower-level browser/shell probe.
"""
