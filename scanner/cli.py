"""
CLI interface for LLM Fuzzing Scanner.

Commands:
    scanner init                    -- Initialize DB and load seeds
    scanner scan simple             -- Simple mode scan
    scanner scan advanced           -- Advanced mode scan (YAML config)
    scanner ammo list               -- List prompts
    scanner ammo add                -- Add prompt
    scanner ammo show <id>          -- Show prompt details
    scanner attacks list            -- List attacks
    scanner attacks show <name>     -- Show attack details
    scanner detectors list          -- List detector substrings
    scanner attackers list          -- List attacker instructions
    scanner judges list             -- List judge instructions
    scanner tools list              -- List tools
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from scanner.config import TargetConfig
from scanner.data.database import get_session, init_db

console = Console()
app = typer.Typer(name="scanner", help="LLM Fuzzing Scanner CLI")
scan_app = typer.Typer(help="Scan commands")
ammo_app = typer.Typer(help="Prompt catalog (ammo) commands")
attacks_app = typer.Typer(help="Attack catalog commands")
detectors_app = typer.Typer(help="Detector substring commands")
attackers_app = typer.Typer(help="Attacker instruction commands")
judges_app = typer.Typer(help="Judge instruction commands")
tools_app = typer.Typer(help="Tool catalog commands")

app.add_typer(scan_app, name="scan")
app.add_typer(ammo_app, name="ammo")
app.add_typer(attacks_app, name="attacks")
app.add_typer(detectors_app, name="detectors")
app.add_typer(attackers_app, name="attackers")
app.add_typer(judges_app, name="judges")
app.add_typer(tools_app, name="tools")


DEFAULT_DB = "sqlite:///scanner.db"
ASSETS_DIR = Path(__file__).parent / "assets"


def _get_engine(db_url: str = DEFAULT_DB):
    return init_db(db_url)


# ---------------------------------------------------------------------------
# INIT
# ---------------------------------------------------------------------------


@app.command()
def init(
    db_url: str = typer.Option(DEFAULT_DB, help="Database URL"),
    assets: str = typer.Option(str(ASSETS_DIR), help="Path to assets directory with seed files"),
    attacks_dir: str = typer.Option(
        str(Path(__file__).parent.parent / "config" / "attacks"),
        help="Path to directory with attack bundle YAML files",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Initialize database and load seed data."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    console.print("[bold green]Initializing database...[/]")
    engine = _get_engine(db_url)

    session = get_session(engine)
    try:
        from scanner.catalogs.seed_loader import SeedLoader
        loader = SeedLoader(session)

        # Step 1: load component seeds (prompts, instructions, detectors, tools)
        counts = loader.load_all(assets)
        console.print("[bold green]Seed data loaded:[/]")
        for key, count in counts.items():
            console.print(f"  {key}: {count}")

        # Step 2: load attack bundles from config/attacks/
        attacks_path = Path(attacks_dir)
        if attacks_path.exists():
            attack_count = loader._load_attacks(attacks_path)
            console.print(f"  attack bundles: {attack_count}")
        else:
            console.print(f"[yellow]Attacks dir not found: {attacks_path}[/]")
    finally:
        session.close()

    console.print("[bold green]Done![/]")


# ---------------------------------------------------------------------------
# SCAN SIMPLE
# ---------------------------------------------------------------------------


@scan_app.command("simple")
def scan_simple(
    url: str = typer.Option(..., help="Target LLM base URL"),
    model: str = typer.Option(..., help="Target model name"),
    api_key: str = typer.Option("dummy", help="API key for target"),
    attack_names: str = typer.Option(..., "--attacks", help="Comma-separated attack names"),
    attacker_url: Optional[str] = typer.Option(None, help="Attacker LLM base URL"),
    attacker_model: Optional[str] = typer.Option(None, help="Attacker model name"),
    attacker_api_key: str = typer.Option("dummy", help="Attacker API key"),
    judge_url: Optional[str] = typer.Option(None, help="Judge LLM base URL"),
    judge_model: Optional[str] = typer.Option(None, help="Judge model name"),
    judge_api_key: str = typer.Option("dummy", help="Judge API key"),
    max_prompts: int = typer.Option(100, help="Max prompts per attack"),
    output_dir: str = typer.Option("./reports", help="Output directory for reports"),
    db_url: str = typer.Option(DEFAULT_DB, help="Database URL"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run a simple scan with predefined attacks."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    engine = _get_engine(db_url)
    session = get_session(engine)

    target_cfg = TargetConfig(url=url, model=model, api_key=api_key)

    attacker_cfg = None
    if attacker_url and attacker_model:
        attacker_cfg = TargetConfig(url=attacker_url, model=attacker_model, api_key=attacker_api_key)

    judge_cfg = None
    if judge_url and judge_model:
        judge_cfg = TargetConfig(url=judge_url, model=judge_model, api_key=judge_api_key)

    from scanner.engine.scan_engine import ScanEngine

    names = [n.strip() for n in attack_names.split(",")]
    console.print(f"[bold]Running simple scan against {model} @ {url}[/]")
    console.print(f"[bold]Attacks: {names}[/]")

    scan = ScanEngine(session, target_cfg, attacker_cfg, judge_cfg)
    try:
        result = scan.run_simple(names, max_prompts)
    finally:
        session.close()

    _output_results(result, output_dir)


# ---------------------------------------------------------------------------
# SCAN ADVANCED
# ---------------------------------------------------------------------------


@scan_app.command("advanced")
def scan_advanced(
    config_path: str = typer.Argument(..., help="Path to YAML config file"),
    db_url: str = typer.Option(DEFAULT_DB, help="Database URL"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run an advanced scan from YAML configuration."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    import yaml
    from scanner.config import AdvancedConfig

    config_file = Path(config_path)
    if not config_file.exists():
        console.print(f"[red]Config file not found: {config_path}[/]")
        raise typer.Exit(1)

    raw = yaml.safe_load(config_file.read_text(encoding="utf-8"))
    config = AdvancedConfig(**raw)

    engine_db = _get_engine(db_url)
    session = get_session(engine_db)

    target_cfg = config.scan.target
    attacker_cfg = config.scan.attacker
    judge_cfg = config.scan.judge

    from scanner.catalogs.catalogs import AttackCatalog
    from scanner.engine.scan_engine import ScanEngine

    catalog = AttackCatalog(session)
    attack_names = [a.name for a in config.attacks]
    attacks = catalog.get_by_names(attack_names)

    if not attacks:
        console.print("[red]No attacks found in DB matching config.[/]")
        raise typer.Exit(1)

    console.print(f"[bold]Running advanced scan with {len(attacks)} attacks[/]")

    scan = ScanEngine(session, target_cfg, attacker_cfg, judge_cfg)
    try:
        result = scan.run_advanced(attacks, max_prompts_per_attack=100)
    finally:
        session.close()

    _output_results(result, config.scan.output_dir)


# ---------------------------------------------------------------------------
# Report output helper
# ---------------------------------------------------------------------------


def _output_results(result, output_dir: str) -> None:
    from scanner.reports.generator import generate_json_report, generate_md_report

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    md_path = generate_md_report(result, out / f"report_{result.session_id}.md")
    json_path = generate_json_report(result, out / f"report_{result.session_id}.json")

    console.print("")
    console.print("[bold green]Scan complete![/]")
    console.print(f"  Total attacks: {result.total_attacks}")
    console.print(f"  Total prompts: {result.total_prompts}")
    console.print(f"  Total hits:    {result.total_hits}")
    console.print(f"  Success rate:  {result.overall_success_rate * 100:.1f}%")
    console.print(f"  Duration:      {result.duration_seconds:.1f}s")
    console.print("")
    console.print(f"  MD report:   {md_path}")
    console.print(f"  JSON report: {json_path}")


# ---------------------------------------------------------------------------
# AMMO (Prompts)
# ---------------------------------------------------------------------------


@ammo_app.command("list")
def ammo_list(
    source: Optional[str] = typer.Option(None, help="Filter by source"),
    language: Optional[str] = typer.Option(None, help="Filter by language"),
    limit: int = typer.Option(50, help="Max items"),
    db_url: str = typer.Option(DEFAULT_DB),
) -> None:
    """List prompts (ammo)."""
    engine = _get_engine(db_url)
    session = get_session(engine)
    from scanner.catalogs.catalogs import PromptCatalog
    catalog = PromptCatalog(session)

    filters = {}
    if source:
        filters["source"] = source
    if language:
        filters["language"] = language

    items = catalog.list_all(limit=limit, **filters)
    table = Table(title="Prompts (Ammo)")
    table.add_column("ID", max_width=8)
    table.add_column("Source")
    table.add_column("Language")
    table.add_column("Tags")
    table.add_column("Content", max_width=60)

    for p in items:
        table.add_row(
            p.id[:8],
            p.source,
            p.language,
            p.tags,
            p.content[:60] + ("..." if len(p.content) > 60 else ""),
        )

    console.print(table)
    console.print(f"Total: {len(items)}")
    session.close()


@ammo_app.command("show")
def ammo_show(
    prompt_id: str = typer.Argument(..., help="Prompt ID (or prefix)"),
    db_url: str = typer.Option(DEFAULT_DB),
) -> None:
    """Show prompt details."""
    engine = _get_engine(db_url)
    session = get_session(engine)
    from scanner.catalogs.catalogs import PromptCatalog
    catalog = PromptCatalog(session)

    item = catalog.get(prompt_id)
    if not item:
        # Try prefix search
        all_items = catalog.list_all(active_only=False, limit=10000)
        matches = [p for p in all_items if p.id.startswith(prompt_id)]
        if matches:
            item = matches[0]

    if not item:
        console.print(f"[red]Prompt not found: {prompt_id}[/]")
        session.close()
        raise typer.Exit(1)

    console.print(f"[bold]ID:[/] {item.id}")
    console.print(f"[bold]Source:[/] {item.source}")
    console.print(f"[bold]Language:[/] {item.language}")
    console.print(f"[bold]Tags:[/] {item.tags}")
    console.print(f"[bold]Active:[/] {item.is_active}")
    console.print(f"[bold]Content:[/]\n{item.content}")
    session.close()


@ammo_app.command("add")
def ammo_add(
    content: str = typer.Option(..., help="Prompt content"),
    source: str = typer.Option("custom", help="Source label"),
    language: str = typer.Option("en", help="Language"),
    tags: Optional[str] = typer.Option(None, help="Comma-separated tags"),
    db_url: str = typer.Option(DEFAULT_DB),
) -> None:
    """Add a new prompt."""
    engine = _get_engine(db_url)
    session = get_session(engine)
    from scanner.catalogs.catalogs import PromptCatalog
    catalog = PromptCatalog(session)

    tag_list = [t.strip() for t in tags.split(",")] if tags else []
    item = catalog.add_prompt(content=content, source=source, language=language, tags=tag_list)
    console.print(f"[green]Added prompt: {item.id}[/]")
    session.close()


# ---------------------------------------------------------------------------
# ATTACKS
# ---------------------------------------------------------------------------


@attacks_app.command("list")
def attacks_list(
    category: Optional[str] = typer.Option(None, help="Filter by category"),
    db_url: str = typer.Option(DEFAULT_DB),
) -> None:
    """List attacks."""
    engine = _get_engine(db_url)
    session = get_session(engine)
    from scanner.catalogs.catalogs import AttackCatalog
    catalog = AttackCatalog(session)

    filters = {}
    if category:
        filters["category"] = category

    items = catalog.list_all(**filters)
    table = Table(title="Attacks")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Orchestrator")
    table.add_column("Scorer")
    table.add_column("Prompts")
    table.add_column("Tools")

    for a in items:
        table.add_row(
            a.name,
            a.category,
            a.orchestrator_type,
            a.scorer_type,
            str(len(a.prompts)),
            str(len(a.tools)),
        )

    console.print(table)
    session.close()


@attacks_app.command("show")
def attacks_show(
    name: str = typer.Argument(..., help="Attack name"),
    db_url: str = typer.Option(DEFAULT_DB),
) -> None:
    """Show attack details."""
    engine = _get_engine(db_url)
    session = get_session(engine)
    from scanner.catalogs.catalogs import AttackCatalog
    catalog = AttackCatalog(session)

    item = catalog.get_by_name(name)
    if not item:
        console.print(f"[red]Attack not found: {name}[/]")
        session.close()
        raise typer.Exit(1)

    console.print(f"[bold]Name:[/] {item.name}")
    console.print(f"[bold]Category:[/] {item.category}")
    console.print(f"[bold]Description:[/] {item.description}")
    console.print(f"[bold]Orchestrator:[/] {item.orchestrator_type}")
    console.print(f"[bold]Scorer:[/] {item.scorer_type}")
    console.print(f"[bold]Max Turns:[/] {item.max_turns}")
    console.print(f"[bold]Negation:[/] {item.is_negation}")
    console.print(f"[bold]Prompts:[/] {len(item.prompts)}")
    console.print(f"[bold]Detector Substrings:[/] {len(item.detector_substrings)}")
    console.print(f"[bold]Tools:[/] {len(item.tools)}")

    if item.attacker_instruction:
        console.print(f"[bold]Attacker Instruction:[/] {item.attacker_instruction.name}")
    if item.judge_instruction:
        console.print(f"[bold]Judge Instruction:[/] {item.judge_instruction.name}")

    session.close()


# ---------------------------------------------------------------------------
# DETECTORS
# ---------------------------------------------------------------------------


@detectors_app.command("list")
def detectors_list(
    source: Optional[str] = typer.Option(None),
    db_url: str = typer.Option(DEFAULT_DB),
) -> None:
    """List detector substrings."""
    engine = _get_engine(db_url)
    session = get_session(engine)
    from scanner.catalogs.catalogs import DetectorCatalog
    catalog = DetectorCatalog(session)

    filters = {}
    if source:
        filters["source"] = source

    items = catalog.list_all(**filters)
    table = Table(title="Detector Substrings")
    table.add_column("ID", max_width=8)
    table.add_column("Substring", max_width=40)
    table.add_column("Negation")
    table.add_column("Source")

    for d in items:
        table.add_row(d.id[:8], d.substring[:40], str(d.is_negation), d.source)

    console.print(table)
    session.close()


# ---------------------------------------------------------------------------
# ATTACKERS
# ---------------------------------------------------------------------------


@attackers_app.command("list")
def attackers_list(db_url: str = typer.Option(DEFAULT_DB)) -> None:
    """List attacker instructions."""
    engine = _get_engine(db_url)
    session = get_session(engine)
    from scanner.catalogs.catalogs import AttackerCatalog
    catalog = AttackerCatalog(session)

    items = catalog.list_all()
    table = Table(title="Attacker Instructions")
    table.add_column("Name")
    table.add_column("Description", max_width=60)

    for a in items:
        table.add_row(a.name, a.description[:60])

    console.print(table)
    session.close()


# ---------------------------------------------------------------------------
# JUDGES
# ---------------------------------------------------------------------------


@judges_app.command("list")
def judges_list(db_url: str = typer.Option(DEFAULT_DB)) -> None:
    """List judge instructions."""
    engine = _get_engine(db_url)
    session = get_session(engine)
    from scanner.catalogs.catalogs import JudgeCatalog
    catalog = JudgeCatalog(session)

    items = catalog.list_all()
    table = Table(title="Judge Instructions")
    table.add_column("Name")
    table.add_column("True Description", max_width=60)

    for j in items:
        table.add_row(j.name, j.true_description[:60])

    console.print(table)
    session.close()


# ---------------------------------------------------------------------------
# TOOLS
# ---------------------------------------------------------------------------


@tools_app.command("list")
def tools_list(db_url: str = typer.Option(DEFAULT_DB)) -> None:
    """List tools."""
    engine = _get_engine(db_url)
    session = get_session(engine)
    from scanner.catalogs.catalogs import ToolCatalog
    catalog = ToolCatalog(session)

    items = catalog.list_all()
    table = Table(title="Tools")
    table.add_column("Name")
    table.add_column("Description", max_width=60)

    for t in items:
        table.add_row(t.name, t.description[:60])

    console.print(table)
    session.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
