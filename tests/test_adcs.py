"""
Tests for ADCSCollector — covers ESC1/ESC2/ESC3 detection logic.
All tests use mocked LDAP — no live AD CS instance required.
"""
import json

import pytest

from adenum.adcs import (
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
    EKU_ANY_PURPOSE,
    EKU_CERT_REQ_AGENT,
    ADCSCollectionResult,
    ADCSCollector,
)


def make_collector():
    return ADCSCollector(domain="corp.local", dc_ip="10.10.10.5",
                         username="svc", password="pw")


# ------------------------------------------------------------------
# ESC1: enrollee can supply SAN
# ------------------------------------------------------------------

def test_flag_esc1_true_when_enrollee_supplies_subject():
    t = {"mspki_certificate_name_flag": CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT}
    assert ADCSCollector._flag_esc1(t) is True


def test_flag_esc1_false_when_flag_not_set():
    t = {"mspki_certificate_name_flag": 0}
    assert ADCSCollector._flag_esc1(t) is False


def test_flag_esc1_handles_none_flag():
    t = {"mspki_certificate_name_flag": None}
    assert ADCSCollector._flag_esc1(t) is False


def test_flag_esc1_handles_missing_key():
    assert ADCSCollector._flag_esc1({}) is False


# ------------------------------------------------------------------
# ESC2: Any Purpose EKU / no EKU
# ------------------------------------------------------------------

def test_flag_esc2_true_when_any_purpose_eku():
    t = {"pkiextendedkeyusage": [EKU_ANY_PURPOSE]}
    assert ADCSCollector._flag_esc2(t) is True


def test_flag_esc2_true_when_no_eku():
    """No EKU restrictions = any purpose by default."""
    t = {"pkiextendedkeyusage": []}
    assert ADCSCollector._flag_esc2(t) is True


def test_flag_esc2_true_when_eku_key_missing():
    assert ADCSCollector._flag_esc2({}) is True


def test_flag_esc2_false_when_specific_eku_only():
    t = {"pkiextendedkeyusage": ["1.3.6.1.5.5.7.3.2"]}   # Client Auth only
    assert ADCSCollector._flag_esc2(t) is False


# ------------------------------------------------------------------
# ESC3: Certificate Request Agent EKU
# ------------------------------------------------------------------

def test_flag_esc3_true_when_agent_eku():
    t = {"pkiextendedkeyusage": [EKU_CERT_REQ_AGENT]}
    assert ADCSCollector._flag_esc3(t) is True


def test_flag_esc3_true_when_in_app_policies():
    t = {
        "pkiextendedkeyusage": [],
        "mspki_certificate_application_policy": [EKU_CERT_REQ_AGENT],
    }
    assert ADCSCollector._flag_esc3(t) is True


def test_flag_esc3_false_when_no_agent_eku():
    t = {"pkiextendedkeyusage": ["1.3.6.1.5.5.7.3.2"]}
    assert ADCSCollector._flag_esc3(t) is False


# ------------------------------------------------------------------
# ADCSCollectionResult.esc_findings()
# ------------------------------------------------------------------

def test_esc_findings_groups_correctly():
    result = ADCSCollectionResult(
        domain="corp.local",
        collected_at="2026-01-01T00:00:00Z",
        templates=[
            {"cn": "ESC1Template", "dn": "CN=ESC1Template,...", "esc1": True,  "esc2": False, "esc3": False},
            {"cn": "ESC2Template", "dn": "CN=ESC2Template,...", "esc1": False, "esc2": True,  "esc3": False},
            {"cn": "ESC3Template", "dn": "CN=ESC3Template,...", "esc1": False, "esc2": False, "esc3": True},
            {"cn": "SafeTemplate",  "dn": "CN=Safe,...",         "esc1": False, "esc2": False, "esc3": False},
        ],
    )
    findings = result.esc_findings()
    assert len(findings["ESC1"]) == 1
    assert findings["ESC1"][0]["template"] == "ESC1Template"
    assert len(findings["ESC2"]) == 1
    assert len(findings["ESC3"]) == 1
    assert len([t for f in findings.values() for t in f if t["template"] == "SafeTemplate"]) == 0


def test_esc_findings_empty_when_no_templates():
    result = ADCSCollectionResult(domain="corp.local", collected_at="x", templates=[])
    findings = result.esc_findings()
    assert findings == {"ESC1": [], "ESC2": [], "ESC3": []}


# ------------------------------------------------------------------
# JSON serialization
# ------------------------------------------------------------------

def test_adcs_collection_result_writes_json(tmp_path):
    result = ADCSCollectionResult(
        domain="corp.local",
        collected_at="2026-01-01T00:00:00Z",
        templates=[{"cn": "UserTemplate", "dn": "CN=UserTemplate,...", "esc1": True, "esc2": False, "esc3": False}],
    )
    out_path = result.to_json(tmp_path)
    assert out_path.exists()
    data = json.loads(out_path.read_text())
    assert data["domain"] == "corp.local"
    assert len(data["templates"]) == 1


# ------------------------------------------------------------------
# Collector constructor
# ------------------------------------------------------------------

def test_adcs_collector_base_dn():
    c = make_collector()
    assert c.base_dn == "DC=corp,DC=local"


def test_adcs_collector_raises_without_connect(mocker):
    c = make_collector()
    with pytest.raises(RuntimeError):
        c._search_templates()
