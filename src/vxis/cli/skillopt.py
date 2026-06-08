from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from vxis.skillopt_bridge import (
    export_searchqa_split,
    import_optimized_skill,
    list_optimized_skills,
    load_optimized_skill,
)

skillopt_app = typer.Typer(
    help="Bridge VXIS cases and optimized SkillOpt best_skill.md artifacts",
    no_args_is_help=True,
)


@skillopt_app.command("export")
def export_cases(
    case_file: Path = typer.Argument(..., help="JSON/JSONL VXIS case records."),
    out_dir: Path = typer.Option(..., "--out", "-o", help="Output SkillOpt split directory."),
    train_ratio: float = typer.Option(0.6, "--train-ratio", min=0.1, max=1.0),
    val_ratio: float = typer.Option(0.2, "--val-ratio", min=0.0, max=0.9),
    seed: int = typer.Option(42, "--seed"),
) -> None:
    """Export VXIS next-action cases as a SkillOpt searchqa-compatible split."""
    result = export_searchqa_split(
        case_file,
        out_dir,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
        seed=seed,
    )
    typer.echo(
        f"exported {result.total} case(s): "
        f"train={result.train} val={result.val} test={result.test}"
    )
    typer.echo(f"config: {result.config_path}")
    typer.echo(f"seed skill: {result.seed_skill_path}")


@skillopt_app.command("import")
def import_skill(
    skill_path: Path = typer.Argument(..., help="SkillOpt outputs/.../best_skill.md path."),
    name: str = typer.Option(..., "--name", "-n", help="VXIS optimized skill name."),
    surface: str = typer.Option("web", "--surface"),
    families: str = typer.Option("", "--families", help="Comma-separated families."),
    roles: str = typer.Option("director", "--roles", help="Comma-separated roles."),
    triggers: str = typer.Option("", "--triggers", help="Comma-separated trigger terms."),
    inactive: bool = typer.Option(False, "--inactive", help="Import but do not inject into prompts."),
) -> None:
    """Import a SkillOpt best_skill.md artifact into VXIS prompt guidance."""
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
            f"{entry.name}\t{status}\t{entry.surface}\t"
            f"{','.join(entry.families)}\t{entry.path}"
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


def _split(value: Optional[str]) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]
