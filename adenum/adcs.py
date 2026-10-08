"""
ADenum ADCS Collector
Enumerates Active Directory Certificate Services (AD CS) certificate
templates for ESC1–ESC3 style misconfigurations (as defined by
SpecterOps "Certified Pre-Owned" research).

  ESC1 — Any authenticated user can enroll AND the template allows
          Subject Alternative Name (SAN) specification by the requestor.
          An attacker can request a cert for any user, including Domain Admin.

  ESC2 — Template has the "Any Purpose" EKU or no EKU (acts as Subordinate CA).
          Certificate can be used for any purpose.

  ESC3 — Template has the "Certificate Request Agent" EKU.
          Allows an attacker to request certs on behalf of other users.

Requires read-only LDAP access; does not modify AD CS state.
"""
from __future__ import annotations

import datetime
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import ClassVar

from ldap3 import ALL, NTLM, SUBTREE, Connection, Server

# ---------------------------------------------------------------------------
# OIDs used for EKU matching
# ---------------------------------------------------------------------------
EKU_ANY_PURPOSE    = "2.5.29.37.0"
EKU_CERT_REQ_AGENT = "1.3.6.1.4.1.311.20.2.1"
EKU_CLIENT_AUTH    = "1.3.6.1.5.5.7.3.2"

# msPKI-Certificate-Name-Flag bit: ENROLLEE_SUPPLIES_SUBJECT (0x00000001)
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
# msPKI-Enrollment-Flag bit: INCLUDE_SYMMETRIC_ALGORITHMS, not relevant here
# msPKI-RA-Signature == 0 means no authorized signature required (weaker)


@dataclass
class ADCSCollectionResult:
    domain: str
    collected_at: str
    templates: list = field(default_factory=list)

    def to_json(self, out_dir: Path) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"adenum_adcs_{self.domain}.json"
        out_path.write_text(json.dumps(asdict(self), indent=2, default=str))
        return out_path

    def esc_findings(self) -> dict[str, list[dict]]:
        """Return a dict of ESC category → list of vulnerable templates."""
        esc1, esc2, esc3 = [], [], []
        for t in self.templates:
            if t.get("esc1"):
                esc1.append({"template": t.get("cn"), "dn": t.get("dn")})
            if t.get("esc2"):
                esc2.append({"template": t.get("cn"), "dn": t.get("dn")})
            if t.get("esc3"):
                esc3.append({"template": t.get("cn"), "dn": t.get("dn")})
        return {"ESC1": esc1, "ESC2": esc2, "ESC3": esc3}


class ADCSCollector:
    """Collect and flag ADCS certificate template misconfigurations."""

    TEMPLATE_ATTRS: ClassVar[list[str]] = [
        "cn",
        "displayName",
        "msPKI-Certificate-Name-Flag",
        "msPKI-Enrollment-Flag",
        "msPKI-RA-Signature",
        "msPKI-Certificate-Application-Policy",   # Application policies / EKUs
        "pKIExtendedKeyUsage",                     # Extended Key Usage OIDs
        "nTSecurityDescriptor",
        "objectGUID",
    ]

    def __init__(
        self,
        domain: str,
        dc_ip: str,
        username: str,
        password: str | None = None,
        ldap_port: int = 389,
        use_ssl: bool = False,
        nt_hash: str | None = None,
    ):
        self.domain    = domain
        self.dc_ip     = dc_ip
        self.username  = username
        self.password  = password
        self.ldap_port = ldap_port
        self.use_ssl   = use_ssl
        self.nt_hash   = nt_hash
        self.base_dn   = ",".join(f"DC={p}" for p in domain.split("."))
        self.conn: Connection | None = None

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> Connection:
        server = Server(self.dc_ip, port=self.ldap_port, use_ssl=self.use_ssl, get_info=ALL)
        bind_user = f"{self.domain}\\{self.username}"
        bind_pass = (
            f"aad3b435b51404eeaad3b435b51404ee:{self.nt_hash}"
            if self.nt_hash
            else self.password
        )
        self.conn = Connection(
            server, user=bind_user, password=bind_pass,
            authentication=NTLM, auto_bind=True,
        )
        return self.conn

    def _search_templates(self) -> list[dict]:
        if self.conn is None:
            raise RuntimeError("call connect() first")

        config_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{self.base_dn}"
        self.conn.search(
            search_base=config_dn,
            search_filter="(objectClass=pKICertificateTemplate)",
            search_scope=SUBTREE,
            attributes=self.TEMPLATE_ATTRS,
            paged_size=500,
        )
        results = []
        for entry in self.conn.entries:
            row = {"dn": entry.entry_dn}
            for attr in self.TEMPLATE_ATTRS:
                if attr in entry:
                    val = entry[attr].value
                    row[attr.lower().replace("-", "_")] = val
            results.append(row)
        return results

    # ------------------------------------------------------------------
    # ESC detection helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _flag_esc1(template: dict) -> bool:
        """ESC1: enrollee can supply SAN + any user can enroll."""
        name_flag = template.get("mspki_certificate_name_flag") or 0
        try:
            name_flag = int(name_flag)
        except (TypeError, ValueError):
            name_flag = 0
        return bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)

    @staticmethod
    def _flag_esc2(template: dict) -> bool:
        """ESC2: Any Purpose EKU or no EKU restrictions."""
        ekus: list = template.get("pkiextendedkeyusage") or []
        if isinstance(ekus, str):
            ekus = [ekus]
        if not ekus:        # no EKU = any purpose by default
            return True
        return EKU_ANY_PURPOSE in ekus

    @staticmethod
    def _flag_esc3(template: dict) -> bool:
        """ESC3: Certificate Request Agent EKU present."""
        ekus: list = template.get("pkiextendedkeyusage") or []
        if isinstance(ekus, str):
            ekus = [ekus]
        app_policies: list = template.get("mspki_certificate_application_policy") or []
        if isinstance(app_policies, str):
            app_policies = [app_policies]
        return EKU_CERT_REQ_AGENT in ekus or EKU_CERT_REQ_AGENT in app_policies

    # ------------------------------------------------------------------
    # Main entry
    # ------------------------------------------------------------------

    def collect_all(self) -> ADCSCollectionResult:
        self.connect()
        try:
            templates = self._search_templates()
            for t in templates:
                t["esc1"] = self._flag_esc1(t)
                t["esc2"] = self._flag_esc2(t)
                t["esc3"] = self._flag_esc3(t)
            result = ADCSCollectionResult(
                domain=self.domain,
                collected_at=datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
                templates=templates,
            )
        finally:
            self.conn.unbind()
        return result
