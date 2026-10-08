"""
ADenum Graph Ingestion
Loads normalized collector JSON into Neo4j as nodes/edges.

Node labels : User, Group, Computer, OU
Edge types  : MemberOf, AdminTo, HasSPN, TrustedForDelegation,
              GenericAll, WriteDacl, WriteOwner, ForceChangePassword
"""
from __future__ import annotations

import json
from pathlib import Path

from neo4j import GraphDatabase


class GraphIngestor:
    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def wipe(self):
        with self.driver.session() as s:
            s.run("MATCH (n) DETACH DELETE n")

    # FIX #7: Create uniqueness constraints so MERGE is O(1) instead of O(n)
    def create_indexes(self):
        """Create uniqueness constraints on :dn for each node label.

        Safe to call repeatedly — uses IF NOT EXISTS so it is idempotent.
        """
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:User)     REQUIRE n.dn IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Group)    REQUIRE n.dn IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Computer) REQUIRE n.dn IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:OU)       REQUIRE n.dn IS UNIQUE",
        ]
        with self.driver.session() as s:
            for stmt in constraints:
                s.run(stmt)

    def ingest_file(self, json_path: Path) -> dict:
        data   = json.loads(Path(json_path).read_text())
        stats  = {"users": 0, "groups": 0, "computers": 0, "ous": 0, "edges": 0}

        # Ensure indexes exist before heavy MERGE work
        self.create_indexes()

        with self.driver.session() as session:
            for u in data.get("users", []):
                session.execute_write(self._merge_user, u)
                stats["users"] += 1
            for g in data.get("groups", []):
                session.execute_write(self._merge_group, g)
                stats["groups"] += 1
            for c in data.get("computers", []):
                session.execute_write(self._merge_computer, c)
                stats["computers"] += 1
            for ou in data.get("ous", []):
                session.execute_write(self._merge_ou, ou)
                stats["ous"] += 1

            # Second pass: relationships (all nodes must exist first)
            for g in data.get("groups", []):
                stats["edges"] += session.execute_write(self._link_members, g)

        return stats

    # ------------------------------------------------------------------
    # Node writers
    # ------------------------------------------------------------------
    @staticmethod
    def _merge_user(tx, u: dict):
        tx.run(
            """
            MERGE (n:User {dn: $dn})
            SET n.name           = $name,
                n.kerberoastable = $kerb,
                n.asrep_roastable = $asrep,
                n.disabled       = $disabled,
                n.not_delegatable = $not_del,
                n.high_value     = $hv
            """,
            dn=u["dn"],
            name=u.get("sAMAccountName"),
            kerb=u.get("kerberoastable", False),
            asrep=u.get("asrep_roastable", False),
            disabled=u.get("disabled", False),
            not_del=u.get("not_delegatable", False),
            hv=bool(u.get("adminCount")),
        )

    @staticmethod
    def _merge_group(tx, g: dict):
        tx.run(
            """
            MERGE (n:Group {dn: $dn})
            SET n.name       = $name,
                n.high_value = $hv
            """,
            dn=g["dn"],
            name=g.get("sAMAccountName"),
            hv=bool(g.get("adminCount")),
        )

    @staticmethod
    def _merge_computer(tx, c: dict):
        tx.run(
            """
            MERGE (n:Computer {dn: $dn})
            SET n.name                    = $name,
                n.os                      = $os,
                n.os_version              = $osv,
                n.unconstrained_delegation = $ud,
                n.constrained_delegation  = $cd,
                n.rbcd_configured         = $rbcd
            """,
            dn=c["dn"],
            name=c.get("sAMAccountName"),
            os=c.get("operatingSystem"),
            osv=c.get("operatingSystemVersion"),
            ud=c.get("unconstrained_delegation", False),
            cd=c.get("constrained_delegation", False),
            rbcd=c.get("rbcd_configured", False),
        )

    @staticmethod
    def _merge_ou(tx, ou: dict):
        tx.run(
            """
            MERGE (n:OU {dn: $dn})
            SET n.name = $name
            """,
            dn=ou["dn"],
            name=ou.get("ou"),
        )

    # ------------------------------------------------------------------
    # Edge writers
    # ------------------------------------------------------------------
    @staticmethod
    def _link_members(tx, g: dict) -> int:
        members = g.get("member") or []
        if isinstance(members, str):
            members = [members]
        count = 0
        for member_dn in members:
            result = tx.run(
                """
                MATCH (g:Group {dn: $gdn})
                MATCH (m {dn: $mdn})
                MERGE (m)-[:MemberOf]->(g)
                RETURN count(*) AS c
                """,
                gdn=g["dn"],
                mdn=member_dn,
            )
            # FIX #6: result.single() returns None when the MATCH finds no rows
            single = result.single()
            count += single["c"] if single is not None else 0
        return count
