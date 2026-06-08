from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from vxis.skillopt_bridge import (
    default_run_dir,
    default_split_dir,
    export_searchqa_split,
    import_optimized_skill,
    latest_best_skill,
    list_optimized_skills,
    load_optimized_skill,
    run_skillopt_train,
    set_optimized_skill_active,
)

HELP = """SkillOpt is not a background daemon.

Typical manual flow:

  vxis skillopt prepare axis2 --cases cases.jsonl
  vxis skillopt train axis2 --dry-run
  vxis skillopt train axis2 --execute
  vxis skillopt apply axis2 --inactive
  vxis skillopt show axis2
  vxis skillopt enable axis2

One-shot guided flow:

  vxis skillopt run axis2 --cases cases.jsonl --dry-run
  vxis skillopt run axis2 --cases cases.jsonl --execute --auto-apply

Safety model:

  - prepare/export only creates a SkillOpt-compatible dataset.
  - train runs local /Users/eliot/Desktop/gitt/SkillOpt when --execute is set.
  - apply/import copies best_skill.md into VXIS.
  - imported skills only affect VXIS prompts when active.
"""

skillopt_app = typer.Typer(
    help=HELP,
    no_args_is_help=True,
)


@skillopt_app.command("prepare")
def prepare_cases(
    name: str = typer.Argument(..., help="Experiment name, e.g. axis2."),
    case_file: Path = typer.Option(..., "--cases", "-c", help="JSON/JSONL VXIS case records."),
    out_dir: Optional[Path] = typer.Option(None, "--out", "-o", help="Output split directory."),
    train_ratio: float = typer.Option(0.6, "--train-ratio", min=0.1, max=1.0),
    val_ratio: float = typer.Option(0.2, "--val-ratio", min=0.0, max=0.9),
    seed: int = typer.Option(42, "--seed"),
) -> None:
    """Create a SkillOpt dataset for NAME from VXIS cases.

    Example:

      vxis skillopt prepare axis2 --cases cases.jsonl

    Output defaults to ~/.vxis/skillopt/splits/axis2.
    """
    _export(case_file, out_dir or default_split_dir(name), train_ratio, val_ratio, seed)
    typer.echo(f"next: vxis skillopt train {name} --dry-run")
    typer.echo(f"then: vxis skillopt train {name} --execute")
    typer.echo(f"then: vxis skillopt apply {name} --inactive")


@skillopt_app.command("export")
def export_cases(
    case_file: Path = typer.Argument(..., help="JSON/JSONL VXIS case records."),
    out_dir: Path = typer.Option(..., "--out", "-o", help="Output SkillOpt split directory."),
    train_ratio: float = typer.Option(0.6, "--train-ratio", min=0.1, max=1.0),
    val_ratio: float = typer.Option(0.2, "--val-ratio", min=0.0, max=0.9),
    seed: int = typer.Option(42, "--seed"),
) -> None:
    """Alias for prepare when you want to choose the output path directly."""
    _export(case_file, out_dir, train_ratio, val_ratio, seed)


@skillopt_app.command("train")
def train_skill(
    name: str = typer.Argument(..., help="Experiment name, e.g. axis2."),
    config: Optional[Path] = typer.Option(None, "--config", help="SkillOpt config path."),
    checkout: Optional[Path] = typer.Option(None, "--checkout", help="SkillOpt checkout path."),
    out_root: Optional[Path] = typer.Option(None, "--out-root", help="SkillOpt run output root."),
    epochs: Optional[int] = typer.Option(None, "--epochs", min=1),
    workers: Optional[int] = typer.Option(None, "--workers", min=1),
    execute: bool = typer.Option(False, "--execute", help="Actually run SkillOpt training."),
    dry_run: bool = typer.Option(
        True, "--dry-run/--no-dry-run", help="Print command without running."
    ),
) -> None:
    """Run or preview local SkillOpt training.

    Default is safe: it prints the command only.

      vxis skillopt train axis2 --dry-run
      vxis skillopt train axis2 --execute
    """
    effective_dry_run = dry_run and not execute
    result = run_skillopt_train(
        name,
        config_path=config,
        checkout=checkout,
        out_root=out_root,
        epochs=epochs,
        workers=workers,
        dry_run=effective_dry_run,
    )
    typer.echo(f"cwd: {result['cwd']}")
    typer.echo("command: " + " ".join(result["command"]))
    if effective_dry_run:
        typer.echo("dry-run only; add --execute to run")
    else:
        typer.echo("training completed")


@skillopt_app.command("apply")
def apply_skill(
    name: str = typer.Argument(..., help="VXIS optimized skill name."),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir", help="SkillOpt run directory."),
    skill_path: Optional[Path] = typer.Option(None, "--skill", help="Explicit best_skill.md path."),
    surface: str = typer.Option("web", "--surface"),
    families: str = typer.Option("", "--families", help="Comma-separated families."),
    roles: str = typer.Option("director", "--roles", help="Comma-separated roles."),
    triggers: str = typer.Option("", "--triggers", help="Comma-separated trigger terms."),
    inactive: bool = typer.Option(
        False, "--inactive", help="Import but do not inject into prompts."
    ),
) -> None:
    """Apply a trained best_skill.md to VXIS.

    Example:

      vxis skillopt apply axis2 --run-dir ~/.vxis/skillopt/runs/axis2 --inactive
      vxis skillopt enable axis2
    """
    source = skill_path or latest_best_skill(run_dir or default_run_dir(name))
    entry = _import(source, name, surface, families, roles, triggers, inactive)
    typer.echo(f"next: vxis skillopt show {entry.name}")
    if inactive:
        typer.echo(f"then: vxis skillopt enable {entry.name}")


@skillopt_app.command("run")
def run_flow(
    name: str = typer.Argument(..., help="Experiment name, e.g. axis2."),
    case_file: Path = typer.Option(..., "--cases", "-c", help="JSON/JSONL VXIS case records."),
    checkout: Optional[Path] = typer.Option(None, "--checkout", help="SkillOpt checkout path."),
    epochs: Optional[int] = typer.Option(None, "--epochs", min=1),
    workers: Optional[int] = typer.Option(None, "--workers", min=1),
    execute: bool = typer.Option(False, "--execute", help="Actually run SkillOpt training."),
    auto_apply: bool = typer.Option(
        False, "--auto-apply", help="Apply best_skill.md after training."
    ),
    inactive: bool = typer.Option(True, "--inactive/--active", help="Apply inactive by default."),
) -> None:
    """Guided one-shot flow: prepare -> train -> optional apply.

    Safe default:

      vxis skillopt run axis2 --cases cases.jsonl

    Real execution:

      vxis skillopt run axis2 --cases cases.jsonl --execute --auto-apply
    """
    split_dir = default_split_dir(name)
    result = export_searchqa_split(case_file, split_dir)
    typer.echo(f"prepared {result.total} cases at {result.out_dir}")
    train_result = run_skillopt_train(
        name,
        config_path=result.config_path,
        checkout=checkout,
        epochs=epochs,
        workers=workers,
        dry_run=not execute,
    )
    typer.echo(f"cwd: {train_result['cwd']}")
    typer.echo("command: " + " ".join(train_result["command"]))
    if not execute:
        typer.echo("dry-run only; add --execute to run training")
        return
    if auto_apply:
        source = latest_best_skill(default_run_dir(name))
        entry = _import(source, name, "web", "", "director", "", inactive)
        typer.echo(f"applied {entry.name}")
    else:
        typer.echo(f"training done; next: vxis skillopt apply {name} --inactive")


@skillopt_app.command("import")
def import_skill(
    skill_path: Path = typer.Argument(..., help="SkillOpt outputs/.../best_skill.md path."),
    name: str = typer.Option(..., "--name", "-n", help="VXIS optimized skill name."),
    surface: str = typer.Option("web", "--surface"),
    families: str = typer.Option("", "--families", help="Comma-separated families."),
    roles: str = typer.Option("director", "--roles", help="Comma-separated roles."),
    triggers: str = typer.Option("", "--triggers", help="Comma-separated trigger terms."),
    inactive: bool = typer.Option(
        False, "--inactive", help="Import but do not inject into prompts."
    ),
) -> None:
    """Import a SkillOpt best_skill.md artifact into VXIS prompt guidance."""
    _import(skill_path, name, surface, families, roles, triggers, inactive)


@skillopt_app.command("list")
def list_skills() -> None:
    """List imported optimized SkillOpt artifacts."""
    entries = list_optimized_skills()
    if not entries:
        typer.echo("no optimized SkillOpt skills imported")
        return
    for entry in entries:
        status = "active" if entry.active else "inactive"
        typer.echo(
            f"{entry.name}\t{status}\t{entry.surface}\t{','.join(entry.families)}\t{entry.path}"
        )


@skillopt_app.command("show")
def show_skill(
    name: str = typer.Argument(..., help="Optimized skill name."),
    max_chars: int = typer.Option(4000, "--max-chars"),
) -> None:
    """Show an imported optimized skill artifact."""
    entry, content = load_optimized_skill(name)
    typer.echo(f"# {entry.name} ({entry.surface})")
    typer.echo(content[:max_chars])


@skillopt_app.command("enable")
def enable_skill(name: str = typer.Argument(..., help="Optimized skill name.")) -> None:
    """Enable an imported optimized skill for prompt injection."""
    entry = set_optimized_skill_active(name, True)
    typer.echo(f"enabled {entry.name}")


@skillopt_app.command("disable")
def disable_skill(name: str = typer.Argument(..., help="Optimized skill name.")) -> None:
    """Disable an imported optimized skill without deleting it."""
    entry = set_optimized_skill_active(name, False)
    typer.echo(f"disabled {entry.name}")


def _export(
    case_file: Path,
    out_dir: Path,
    train_ratio: float,
    val_ratio: float,
    seed: int,
):
    result = export_searchqa_split(
        case_file,
        out_dir,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
        seed=seed,
    )
    typer.echo(
        f"exported {result.total} case(s): train={result.train} val={result.val} test={result.test}"
    )
    typer.echo(f"config: {result.config_path}")
    typer.echo(f"seed skill: {result.seed_skill_path}")
    return result


def _import(
    skill_path: Path,
    name: str,
    surface: str,
    families: str,
    roles: str,
    triggers: str,
    inactive: bool,
):
    entry = import_optimized_skill(
        skill_path,
        name=name,
        surface=surface,
        families=_split(families),
        roles=_split(roles),
        triggers=_split(triggers),
        active=not inactive,
    )
    typer.echo(f"imported optimized skill {entry.name}: {entry.path}")
    return entry


def _split(value: Optional[str]) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]
