from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from vxis.p1.adapters import DryRunAdapter, run_capability
from vxis.p1.audit import AuditLog
from vxis.p1.enforcer import EnforcementError
from vxis.p1.lifecycle import activate, close
from vxis.p1.models import Engagement, Policy, Scope, State, Window, utc_now_iso
from vxis.p1.resolver import DnsResolver
from vxis.p1.store import EngagementStore, p1_home

eng_app = typer.Typer(help="Manage P1 adversary-emulation engagements", no_args_is_help=True)


@eng_app.command("create")
def create_engagement(
    name: str,
    operator: str = typer.Option("BAC", "--operator", help="Customer-visible operator handle."),
    scope: str = typer.Option(..., "--scope", help="Comma-separated allow scope."),
    deny: str = typer.Option("", "--deny", help="Comma-separated explicit exclusions."),
    expiry: str = typer.Option(..., "--expiry", help="Authorization expiry date or ISO datetime."),
    start: Optional[str] = typer.Option(None, "--start", help="Authorization start date."),
    technique: Optional[list[str]] = typer.Option(
        None,
        "--technique",
        "-t",
        help="Allowed technique. Repeat for multiple values.",
    ),
    destructive: bool = typer.Option(False, "--destructive", help="Allow destructive actions."),
    intensity: str = typer.Option("stealth", "--intensity", help="stealth | standard | loud."),
    attest: bool = typer.Option(False, "--attest", help="Attest authorization from the RoE/contract."),
    authorization_ref: Optional[str] = typer.Option(
        None,
        "--authorization-ref",
        help="Optional contract/RoE pointer. Defaults to NAME.",
    ),
) -> None:
    if not attest:
        typer.echo("refused: --attest required for external P1 engagements")
        raise typer.Exit(1)
    engagement_id = _engagement_id(name)
    engagement = Engagement(
        id=engagement_id,
        name=name,
        operator=operator,
        scope=Scope(allow=_split(scope), deny=_split(deny)),
        window=Window(start=start or utc_now_iso()[:10], expiry=expiry),
        policy=Policy(
            techniques=list(technique or ["recon"]),
            intensity=intensity,
            destructive=destructive,
        ),
        attested=True,
        authorization_ref=authorization_ref or name,
    )
    store = EngagementStore()
    store.save(activate(engagement))
    typer.echo(f"created active engagement {engagement.id}")


@eng_app.command("list")
def list_engagements() -> None:
    store = EngagementStore()
    for engagement_id in store.list_ids():
        engagement = store.load(engagement_id)
        typer.echo(f"{engagement.id}\t{engagement.state.value}\t{engagement.operator}\t{engagement.name}")


@eng_app.command("show")
def show_engagement(engagement_id: str) -> None:
    engagement = EngagementStore().load(engagement_id)
    typer.echo(f"id: {engagement.id}")
    typer.echo(f"name: {engagement.name}")
    typer.echo(f"operator: {engagement.operator}")
    typer.echo(f"state: {engagement.state.value}")
    typer.echo(f"attested: {engagement.attested}")
    typer.echo(f"scope.allow: {', '.join(engagement.scope.allow)}")
    typer.echo(f"scope.deny: {', '.join(engagement.scope.deny)}")
    typer.echo(f"window: {engagement.window.start} -> {engagement.window.expiry}")
    typer.echo(f"techniques: {', '.join(engagement.policy.techniques)}")


@eng_app.command("close")
def close_engagement(engagement_id: str) -> None:
    store = EngagementStore()
    engagement = store.load(engagement_id)
    store.save(close(engagement))
    typer.echo(f"closed engagement {engagement.id}")


@eng_app.command("audit")
def audit_status() -> None:
    audit = AuditLog(p1_home() / "audit.jsonl")
    seal = audit.seal()
    status = "valid" if audit.verify() else "invalid"
    typer.echo(f"audit {status}: entries={seal['entries']} head={seal['head_hash']}")


def emulate(
    engagement_id: str = typer.Option(..., "--eng", "--engagement"),
    technique: str = typer.Option(..., "--technique", "-t"),
    target: str = typer.Option(..., "--target"),
    dry_run: bool = typer.Option(True, "--dry-run/--execute", help="P1 adapter mode."),
) -> None:
    engagement = EngagementStore().load(engagement_id)
    if not dry_run:
        typer.echo("refused: no live P1 capability adapter is registered; use --dry-run")
        raise typer.Exit(1)
    try:
        result = run_capability(
            engagement,
            DryRunAdapter(),
            technique=technique,
            target=target,
            options={},
            resolver=DnsResolver(),
            audit=AuditLog(p1_home() / "audit.jsonl"),
            now=utc_now_iso(),
        )
    except EnforcementError as exc:
        typer.echo(f"REFUSED: {exc.reason}")
        raise typer.Exit(1) from exc
    typer.echo(f"ALLOWED dry-run: {result['technique']} {result['target']}")


def _split(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _engagement_id(name: str) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "_" for ch in name).strip("_")
    return f"eng_{slug or 'p1'}"
