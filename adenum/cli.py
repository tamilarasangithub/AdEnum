"""
ADenum CLI
Usage:
    adenum collect  -d corp.local -u svc -p 'Pass123' -dc-ip 10.10.10.5 [--ldap-ssl] [--ldap-port 636]
    adenum collect  -d corp.local -u svc --nt-hash <NTHASH> -dc-ip 10.10.10.5
    adenum collect  -d corp.local -u svc -p 'Pass123' -dc-ip 10.10.10.5 --adcs
    adenum ingest   --input ./collected/adenum_collection_corp.local.json [--wipe]
    adenum query    --kerberoastable
    adenum query    --asrep-roastable
    adenum query    --unconstrained-delegation
    adenum query    --dangerous-acls
    adenum query    --shortest-path --from "jdoe" --to "Domain Admins"
    adenum serve    --port 8080
"""
from __future__ import annotations

import os
from pathlib import Path

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from adenum.adcs import ADCSCollector
from adenum.collector import ADCollector
from adenum.ingest import GraphIngestor
from adenum.query import GraphQueries

load_dotenv()
console = Console()

NEO4J_URI      = os.environ.get("NEO4J_URI",      "bolt://localhost:7687")
NEO4J_USER     = os.environ.get("NEO4J_USER",     "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "adenum123")


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option("0.2.0", prog_name="ADenum")
def cli():
    """ADenum — Active Directory Attack Path Analytics and Vulnerability Mapper

    \b
    Run only against environments you are explicitly authorized to assess.
    """


# ---------------------------------------------------------------------------
# collect
# ---------------------------------------------------------------------------

@cli.command()
@click.option("-d",  "--domain",    required=True,  help="Target domain  (e.g. corp.local)")
@click.option("-u",  "--user",      required=True,  help="Domain username")
@click.option("-p",  "--password",  default=None,   help="Plaintext password")
@click.option("--nt-hash",          default=None,   help="NT hash for pass-the-hash  (LM half omitted)")
@click.option("-dc-ip", "--dc-ip",  required=True,  help="Domain controller IP")
@click.option("--ldap-port",        default=389,    show_default=True, help="LDAP port")        # FIX #4/#10
@click.option("--ldap-ssl",         is_flag=True,   help="Use LDAPS (TLS) — usually port 636")  # FIX #4/#10
@click.option("--adcs",             "collect_adcs", is_flag=True, help="Also enumerate ADCS certificate templates")
@click.option("--out",              default="./collected", show_default=True, help="Output directory for JSON")
def collect(domain, user, password, nt_hash, dc_ip, ldap_port, ldap_ssl, collect_adcs, out):
    """Collect AD objects via LDAP into JSON files."""
    if not password and not nt_hash:
        raise click.UsageError("Provide either -p/--password or --nt-hash")

    console.rule("[bold cyan]ADenum Collector[/]")
    console.print(f"  Domain : [cyan]{domain}[/]")
    console.print(f"  DC     : [cyan]{dc_ip}:{ldap_port}{'  (SSL)' if ldap_ssl else ''}[/]")
    console.print(f"  User   : [cyan]{domain}\\{user}[/]")

    # --- Main AD collection ---
    try:
        collector = ADCollector(
            domain=domain,
            dc_ip=dc_ip,
            username=user,
            password=password,
            ldap_port=ldap_port,
            use_ssl=ldap_ssl,
            nt_hash=nt_hash,
        )
        result   = collector.collect_all()
        out_path = result.to_json(Path(out))

        console.print("\n[bold green]✓ Collection complete[/]")
        console.print(f"  Users     : {len(result.users)}")
        console.print(f"  Groups    : {len(result.groups)}")
        console.print(f"  Computers : {len(result.computers)}")
        console.print(f"  OUs       : {len(result.ous)}")
        console.print(f"  Output    : [green]{out_path}[/]")

        # --- Optional ADCS collection ---
        if collect_adcs:
            console.print("\n[bold cyan]Enumerating ADCS certificate templates...[/]")
            adcs = ADCSCollector(
                domain=domain,
                dc_ip=dc_ip,
                username=user,
                password=password,
                ldap_port=ldap_port,
                use_ssl=ldap_ssl,
                nt_hash=nt_hash,
            )
            adcs_result = adcs.collect_all()
            adcs_path   = adcs_result.to_json(Path(out))
            console.print(f"[green]ADCS: {len(adcs_result.templates)} templates  →  {adcs_path}[/]")

            findings = adcs_result.esc_findings()
            for sev, items in findings.items():
                if items:
                    console.print(f"[bold red]{sev}[/]: {len(items)} finding(s)")
    except Exception as e:  # noqa: BLE001
        console.print(f"\n[bold red]Error during collection:[/] {e}")
        import sys
        sys.exit(1)


# ---------------------------------------------------------------------------
# ingest
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--input",  "input_path", required=True,  type=click.Path(exists=True), help="JSON file from collect")
@click.option("--wipe",   is_flag=True, help="Clear the entire graph before loading")
def ingest(input_path, wipe):
    """Load collected JSON into Neo4j."""
    console.rule("[bold cyan]ADenum Ingestor[/]")
    try:
        ingestor = GraphIngestor(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
        if wipe:
            console.print("[yellow]Wiping existing graph…[/]")
            ingestor.wipe()
        stats = ingestor.ingest_file(Path(input_path))
        ingestor.close()
        console.print("[bold green]✓ Ingest complete[/]")
        for k, v in stats.items():
            console.print(f"  {k:<12}: {v}")
    except Exception as e:  # noqa: BLE001
        console.print(f"\n[bold red]Error during ingestion:[/] {e}")
        import sys
        sys.exit(1)


# ---------------------------------------------------------------------------
# query
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--shortest-path",           "do_shortest",  is_flag=True)
@click.option("--from",                    "from_node",    default=None)
@click.option("--to",                      "to_node",      default=None)
@click.option("--kerberoastable",          "do_kerb",      is_flag=True)
@click.option("--asrep-roastable",         "do_asrep",     is_flag=True)
@click.option("--unconstrained-delegation","do_ud",        is_flag=True)
@click.option("--dangerous-acls",          "do_dacl",      is_flag=True,   # FIX #11
              help="Show dangerous ACL edges targeting high-value objects")
@click.option("--high-value-groups",       "do_hvg",       is_flag=True)
@click.option("--rbcd",                    "do_rbcd",      is_flag=True,
              help="Show computers with RBCD configured")
def query(do_shortest, from_node, to_node, do_kerb, do_asrep,
          do_ud, do_dacl, do_hvg, do_rbcd):
    """Run analysis queries against the Neo4j graph."""
    try:
        gq = GraphQueries(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)

        if do_shortest:
            if not from_node or not to_node:
                raise click.UsageError("--shortest-path requires --from and --to")
            rows  = gq.shortest_path(from_node, to_node)
            table = Table(title=f"Shortest path  {from_node}  →  {to_node}")
            table.add_column("Hops", style="cyan", justify="right")
            table.add_column("Path via nodes",  style="white")
            table.add_column("Relationship types", style="yellow")
            for r in rows:
                table.add_row(
                    str(r.get("hops", "?")),
                    " → ".join(r.get("path", [])),
                    " → ".join(r.get("rels", [])),
                )
            console.print(table)

        if do_kerb:
            rows  = gq.kerberoastable_users()
            table = Table(title="Kerberoastable users  (SPN set, account active)")
            table.add_column("sAMAccountName", style="red")
            table.add_column("DN", style="dim")
            for r in rows:
                table.add_row(r["name"], r["dn"])
            console.print(table)

        if do_asrep:
            rows  = gq.asrep_roastable_users()
            table = Table(title="AS-REP roastable users  (pre-auth disabled)")
            table.add_column("sAMAccountName", style="red")
            table.add_column("DN", style="dim")
            for r in rows:
                table.add_row(r["name"], r["dn"])
            console.print(table)

        if do_ud:
            rows  = gq.unconstrained_delegation_hosts()
            table = Table(title="Unconstrained delegation hosts")
            table.add_column("Computer", style="red")
            table.add_column("OS", style="yellow")
            table.add_column("Version", style="dim")
            for r in rows:
                table.add_row(r["name"], str(r.get("os", "")), str(r.get("os_version", "")))
            console.print(table)

        if do_dacl:                                   # FIX #11
            rows  = gq.dangerous_acls()
            table = Table(title="Dangerous ACL edges on high-value targets")
            table.add_column("Source",      style="cyan")
            table.add_column("Type",        style="dim")
            table.add_column("Right",       style="bold red")
            table.add_column("Target",      style="yellow")
            table.add_column("Target Type", style="dim")
            for r in rows:
                table.add_row(
                    r.get("source", ""),
                    r.get("source_type", ""),
                    r.get("right", ""),
                    r.get("target", ""),
                    r.get("target_type", ""),
                )
            console.print(table)

        if do_hvg:
            rows  = gq.high_value_group_members()
            table = Table(title="High-value group membership (transitive)")
            table.add_column("Group",   style="red")
            table.add_column("Members", style="cyan")
            for r in rows:
                table.add_row(r["group"], ", ".join(r.get("members", [])))
            console.print(table)

        if do_rbcd:
            rows  = gq.rbcd_configured_hosts()
            table = Table(title="Computers with RBCD configured")
            table.add_column("Computer", style="red")
            table.add_column("OS",       style="yellow")
            for r in rows:
                table.add_row(r["name"], str(r.get("os", "")))
            console.print(table)

        gq.close()
    except Exception as e:  # noqa: BLE001
        console.print(f"\n[bold red]Error running query:[/] {e}")
        import sys
        sys.exit(1)


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--port", default=8080, show_default=True, help="Port for the API + graph explorer")
@click.option("--host", default="0.0.0.0", show_default=True)
def serve(port, host):
    """Start the ADenum API server + graph explorer UI."""
    import uvicorn
    console.print(f"[bold cyan]ADenum API server[/]  →  http://{host}:{port}")
    console.print(f"Graph explorer   →  http://localhost:{port}/\n")
    uvicorn.run("adenum.serve:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    cli()
