"""
ADenum API server
FastAPI layer exposing graph queries over HTTP for the graph-explorer
frontend and for scripting / curl usage.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from adenum.query import GraphQueries

# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------

app = FastAPI(
    title="ADenum API",
    description="Active Directory Attack Path Analytics — REST interface",
    version="0.2.0",
)

# CORS — allow the graph-explorer frontend (any origin in dev)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

# Serve static frontend from adenum/static/
_STATIC_DIR = Path(__file__).parent / "static"
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# ---------------------------------------------------------------------------
# Lazy singleton query driver
# ---------------------------------------------------------------------------

_queries: GraphQueries | None = None


def get_queries() -> GraphQueries:
    global _queries
    if _queries is None:
        _queries = GraphQueries(
            uri=os.environ.get("NEO4J_URI",      "bolt://localhost:7687"),
            user=os.environ.get("NEO4J_USER",     "neo4j"),
            password=os.environ.get("NEO4J_PASSWORD", "adenum123"),
        )
    return _queries


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
def index():
    """Serve the graph-explorer frontend."""
    index_html = _STATIC_DIR / "index.html"
    if index_html.exists():
        return FileResponse(str(index_html))
    return {"message": "ADenum API is running. Graph explorer not found in adenum/static/."}


@app.get("/health")
def health():
    """Liveness check."""
    return {"status": "ok", "version": "0.2.0"}


# ---- Graph data (for the vis-network frontend) ----

@app.get("/api/graph")
def api_graph():
    """Return all nodes and edges as vis-network compatible JSON."""
    try:
        data = get_queries().full_graph()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"Neo4j error: {exc}")

    # Transform to vis-network format
    nodes = []
    for n in data["nodes"]:
        label  = n.get("label", "Node")
        name   = n.get("name") or n.get("dn", "?")
        color  = _node_color(n)
        nodes.append({
            "id":    n["id"],
            "label": name,
            "group": label,
            "title": _node_tooltip(n),
            "color": color,
        })

    edges = []
    for e in data["edges"]:
        edges.append({
            "from":  e["from_id"],
            "to":    e["to_id"],
            "label": e.get("type", ""),
            "arrows": "to",
        })

    return {"nodes": nodes, "edges": edges}


def _node_color(n: dict) -> str:
    label = n.get("label", "")
    if n.get("high_value"):
        return "#e53e3e"          # red — high-value target
    if n.get("kerberoastable") or n.get("asrep_roastable"):
        return "#dd6b20"          # orange — roastable
    if n.get("unconstrained_delegation"):
        return "#d69e2e"          # yellow — delegation risk
    if label == "User":
        return "#3182ce"          # blue
    if label == "Group":
        return "#805ad5"          # purple
    if label == "Computer":
        return "#2f855a"          # green
    return "#718096"              # grey — OU / other


def _node_tooltip(n: dict) -> str:
    parts = [f"<b>{n.get('name', '?')}</b>", f"Type: {n.get('label', '?')}"]
    if n.get("kerberoastable"):
        parts.append("⚠ Kerberoastable")
    if n.get("asrep_roastable"):
        parts.append("⚠ AS-REP Roastable")
    if n.get("unconstrained_delegation"):
        parts.append("⚠ Unconstrained Delegation")
    if n.get("high_value"):
        parts.append("🎯 High-Value Target")
    if n.get("disabled"):
        parts.append("✗ Disabled")
    parts.append(f"<small>{n.get('dn', '')}</small>")
    return "<br>".join(parts)


# ---- Finding endpoints ----

@app.get("/api/findings/kerberoastable")
def kerberoastable():
    return get_queries().kerberoastable_users()


@app.get("/api/findings/asrep-roastable")
def asrep_roastable():
    return get_queries().asrep_roastable_users()


@app.get("/api/findings/unconstrained-delegation")
def unconstrained_delegation():
    return get_queries().unconstrained_delegation_hosts()


@app.get("/api/findings/dangerous-acls")
def dangerous_acls():
    return get_queries().dangerous_acls()


@app.get("/api/findings/high-value-groups")
def high_value_groups():
    return get_queries().high_value_group_members()


@app.get("/api/findings/rbcd")
def rbcd():
    return get_queries().rbcd_configured_hosts()


# ---- Path endpoints ----

@app.get("/api/paths/shortest")
def shortest_path(start: str = Query(...), end: str = Query(...)):
    return get_queries().shortest_path(start, end)


@app.get("/api/paths/to-da")
def paths_to_da(start: str = Query(...), max_hops: int = Query(8, le=15)):
    return get_queries().all_paths_to_da(start, max_hops)
