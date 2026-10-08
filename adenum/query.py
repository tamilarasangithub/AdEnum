"""
ADenum Analysis Queries
Canned Cypher queries against the ingested graph: shortest paths to
high-value targets, Kerberoastable accounts, unconstrained delegation,
dangerous ACLs, and more.
"""
from __future__ import annotations

from neo4j import GraphDatabase


class GraphQueries:
    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    # ------------------------------------------------------------------
    # Path queries
    # ------------------------------------------------------------------

    def shortest_path(self, start_name: str, end_name: str) -> list[dict]:
        """Find the shortest attack path between two nodes using ALL relationship types.

        FIX #8: Previously only traversed [:MemberOf] edges, missing AdminTo,
        HasSession, GenericAll, etc. Now uses [*1..10] (all types).
        """
        query = """
        MATCH (start {name: $start}), (end {name: $end})
        MATCH p = shortestPath((start)-[*1..10]->(end))
        RETURN [n IN nodes(p) | n.name] AS path,
               [r IN relationships(p) | type(r)] AS rels,
               length(p) AS hops
        """
        with self.driver.session() as s:
            return [r.data() for r in s.run(query, start=start_name, end=end_name)]

    def all_paths_to_da(self, start_name: str, max_hops: int = 8) -> list[dict]:
        """All paths from a given node to any Domain Admins group (up to max_hops)."""
        query = """
        MATCH (start {name: $start}), (da:Group)
        WHERE da.name =~ '(?i)domain admins.*'
        MATCH p = allShortestPaths((start)-[*1..$hops]->(da))
        RETURN [n IN nodes(p) | n.name] AS path,
               [r IN relationships(p) | type(r)] AS rels,
               length(p) AS hops
        LIMIT 25
        """
        with self.driver.session() as s:
            return [r.data() for r in s.run(query, start=start_name, hops=max_hops)]

    # ------------------------------------------------------------------
    # Finding queries
    # ------------------------------------------------------------------

    def kerberoastable_users(self) -> list[dict]:
        query = """
        MATCH (u:User {kerberoastable: true, disabled: false})
        RETURN u.name AS name, u.dn AS dn
        ORDER BY u.name
        """
        with self.driver.session() as s:
            return [r.data() for r in s.run(query)]

    def asrep_roastable_users(self) -> list[dict]:
        query = """
        MATCH (u:User {asrep_roastable: true, disabled: false})
        RETURN u.name AS name, u.dn AS dn
        ORDER BY u.name
        """
        with self.driver.session() as s:
            return [r.data() for r in s.run(query)]

    def unconstrained_delegation_hosts(self) -> list[dict]:
        query = """
        MATCH (c:Computer {unconstrained_delegation: true})
        RETURN c.name AS name, c.os AS os, c.os_version AS os_version
        ORDER BY c.name
        """
        with self.driver.session() as s:
            return [r.data() for r in s.run(query)]

    def constrained_delegation_hosts(self) -> list[dict]:
        query = """
        MATCH (c:Computer {constrained_delegation: true})
        RETURN c.name AS name, c.os AS os
        ORDER BY c.name
        """
        with self.driver.session() as s:
            return [r.data() for r in s.run(query)]

    def high_value_group_members(self) -> list[dict]:
        query = """
        MATCH (m)-[:MemberOf*1..5]->(g:Group {high_value: true})
        RETURN g.name AS group, collect(DISTINCT m.name) AS members
        ORDER BY g.name
        """
        with self.driver.session() as s:
            return [r.data() for r in s.run(query)]

    def dangerous_acls(self) -> list[dict]:
        """Return ACL edges that allow an attacker to abuse high-value targets.

        FIX #11: This query was documented in the CLI spec but missing from
        both query.py and cli.py.

        Edge types searched:
          GenericAll         — full control
          WriteDacl          — can grant self any right
          WriteOwner         — can take ownership then grant rights
          ForceChangePassword — can reset password without knowing current one
          GenericWrite       — can write arbitrary attributes (e.g. add SPN)
          AddMember          — can add self/other to a sensitive group
        """
        query = """
        MATCH (src)-[r:GenericAll|WriteDacl|WriteOwner|ForceChangePassword|GenericWrite|AddMember]->(dst)
        WHERE dst.high_value = true OR dst:Group
        RETURN src.name AS source,
               labels(src)[0] AS source_type,
               type(r) AS right,
               dst.name AS target,
               labels(dst)[0] AS target_type
        ORDER BY right, dst.name
        """
        with self.driver.session() as s:
            return [r.data() for r in s.run(query)]

    def rbcd_configured_hosts(self) -> list[dict]:
        """Computers with Resource-Based Constrained Delegation configured."""
        query = """
        MATCH (c:Computer {rbcd_configured: true})
        RETURN c.name AS name, c.os AS os
        ORDER BY c.name
        """
        with self.driver.session() as s:
            return [r.data() for r in s.run(query)]

    def full_graph(self) -> dict:
        """Return all nodes and edges for the frontend graph explorer."""
        with self.driver.session() as s:
            nodes_raw = s.run(
                """
                MATCH (n)
                RETURN id(n) AS id,
                       labels(n)[0] AS label,
                       n.name AS name,
                       n.dn AS dn,
                       n.high_value AS high_value,
                       n.disabled AS disabled,
                       n.kerberoastable AS kerberoastable,
                       n.asrep_roastable AS asrep_roastable,
                       n.unconstrained_delegation AS unconstrained_delegation
                """
            )
            edges_raw = s.run(
                """
                MATCH (a)-[r]->(b)
                RETURN id(a) AS from_id,
                       id(b) AS to_id,
                       type(r) AS type
                """
            )
            return {
                "nodes": [r.data() for r in nodes_raw],
                "edges": [r.data() for r in edges_raw],
            }
