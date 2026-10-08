"""
ADenum LDAP Collector
Connects to a Domain Controller and pulls raw AD objects (users, groups,
computers, OUs, ACL/DACL info) into normalized JSON for the ingestion stage.

Requires valid, authorized domain credentials. This module performs read-only
LDAP queries; it does not modify AD state.
"""
from __future__ import annotations

import datetime
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ldap3 import ALL, NTLM, SUBTREE, Connection, Server

# ---- UAC flags for delegation / account checks ----
UAC_ACCOUNTDISABLE         = 0x00000002    # 2
UAC_TRUSTED_FOR_DELEGATION = 0x00080000    # 524288  — unconstrained delegation
UAC_NOT_DELEGATED          = 0x00100000    # 1048576 — account is sensitive / not delegatable
UAC_DONT_REQ_PREAUTH       = 0x00400000    # 4194304 — AS-REP roastable
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000  # constrained delegation (Protocol Transition)


@dataclass
class CollectionResult:
    domain: str
    collected_at: str
    users: list = field(default_factory=list)
    groups: list = field(default_factory=list)
    computers: list = field(default_factory=list)
    ous: list = field(default_factory=list)

    def to_json(self, out_dir: Path) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"adenum_collection_{self.domain}.json"
        out_path.write_text(json.dumps(asdict(self), indent=2, default=str))
        return out_path


class ADCollector:
    def __init__(
        self,
        domain: str,
        dc_ip: str,
        username: str,
        password: str,
        ldap_port: int = 389,
        use_ssl: bool = False,
        nt_hash: str | None = None,
    ):
        self.domain   = domain
        self.dc_ip    = dc_ip
        self.username = username
        self.password = password
        self.ldap_port = ldap_port
        self.use_ssl   = use_ssl
        self.nt_hash   = nt_hash          # optional: pass NTLM hash instead of plaintext password
        self.base_dn   = ",".join(f"DC={p}" for p in domain.split("."))
        self.conn: Connection | None = None

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------
    def connect(self) -> Connection:
        server = Server(
            self.dc_ip,
            port=self.ldap_port,
            use_ssl=self.use_ssl,
            get_info=ALL,
        )
        bind_user = f"{self.domain}\\{self.username}"

        # Support pass-the-hash: format is "LM:NT" — use empty LM half
        if self.nt_hash:
            bind_password = f"aad3b435b51404eeaad3b435b51404ee:{self.nt_hash}"
        else:
            bind_password = self.password

        self.conn = Connection(
            server,
            user=bind_user,
            password=bind_password,
            authentication=NTLM,
            auto_bind=True,
        )
        return self.conn

    def _search(self, ldap_filter: str, attributes: list[str]) -> list[dict]:
        # FIX #1: Use explicit RuntimeError instead of assert (assert is stripped by python -O)
        if self.conn is None:
            raise RuntimeError("LDAP connection is not established — call connect() first")

        self.conn.search(
            search_base=self.base_dn,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=attributes,
            paged_size=1000,
        )
        return [
            {"dn": entry.entry_dn, **{a: entry[a].value for a in attributes if a in entry}}
            for entry in self.conn.entries
        ]

    # ------------------------------------------------------------------
    # Per-object-type collectors
    # ------------------------------------------------------------------
    def collect_users(self) -> list[dict]:
        attrs = [
            "sAMAccountName", "userAccountControl", "memberOf",
            "servicePrincipalName", "pwdLastSet", "adminCount",
            "distinguishedName", "description",
        ]
        raw = self._search("(&(objectCategory=person)(objectClass=user))", attrs)
        for u in raw:
            # FIX #2: Safe int cast — ldap3 may return None, int, or list
            raw_uac = u.get("userAccountControl")
            if isinstance(raw_uac, list):
                raw_uac = raw_uac[0] if raw_uac else 0
            uac = int(raw_uac) if raw_uac is not None else 0

            u["kerberoastable"]  = bool(u.get("servicePrincipalName"))
            u["asrep_roastable"] = bool(uac & UAC_DONT_REQ_PREAUTH)
            u["disabled"]        = bool(uac & UAC_ACCOUNTDISABLE)
            u["not_delegatable"] = bool(uac & UAC_NOT_DELEGATED)   # FIX #5: UAC_NOT_DELEGATED now used
            u["_uac"]            = uac
        return raw

    def collect_groups(self) -> list[dict]:
        attrs = ["sAMAccountName", "member", "adminCount", "description"]
        return self._search("(objectClass=group)", attrs)

    def collect_computers(self) -> list[dict]:
        attrs = [
            "sAMAccountName", "operatingSystem", "operatingSystemVersion",
            "userAccountControl", "msDS-AllowedToDelegateTo",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
        ]
        raw = self._search("(objectClass=computer)", attrs)
        for c in raw:
            raw_uac = c.get("userAccountControl")
            if isinstance(raw_uac, list):
                raw_uac = raw_uac[0] if raw_uac else 0
            uac = int(raw_uac) if raw_uac is not None else 0

            c["unconstrained_delegation"] = bool(uac & UAC_TRUSTED_FOR_DELEGATION)
            c["constrained_delegation"]   = bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)
            rbcd_raw = c.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
            c["rbcd_configured"] = bool(rbcd_raw)
            c["_uac"] = uac
        return raw

    def collect_ous(self) -> list[dict]:
        return self._search("(objectClass=organizationalUnit)", ["ou", "gPLink", "description"])

    def collect_all(self) -> CollectionResult:
        self.connect()
        # FIX #3: Use finally so the LDAP socket is always unbound even if collect_* throws
        try:
            result = CollectionResult(
                domain=self.domain,
                collected_at=datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
                users=self.collect_users(),
                groups=self.collect_groups(),
                computers=self.collect_computers(),
                ous=self.collect_ous(),
            )
        finally:
            self.conn.unbind()
        return result
