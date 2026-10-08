"""
Extended tests for ADCollector — covers all bug fixes from the audit:
  - Bug #1: _search() raises RuntimeError (not AssertionError) when conn is None
  - Bug #2: userAccountControl handled when None or list value
  - Bug #3: collect_all() unbinds LDAP socket even if collect_* throws
  - Bug #5: UAC_NOT_DELEGATED flag is set on user objects
"""
import json

import pytest

from adenum.collector import (
    UAC_DONT_REQ_PREAUTH,
    UAC_NOT_DELEGATED,
    UAC_TRUSTED_FOR_DELEGATION,
    ADCollector,
    CollectionResult,
)


def make_collector():
    return ADCollector(domain="corp.local", dc_ip="10.10.10.5",
                       username="svc", password="pw")


# ------------------------------------------------------------------
# Constructor tests
# ------------------------------------------------------------------

def test_base_dn_built_from_domain():
    c = make_collector()
    assert c.base_dn == "DC=corp,DC=local"


def test_base_dn_three_part_domain():
    c = ADCollector(domain="sub.corp.local", dc_ip="1.2.3.4",
                    username="u", password="p")
    assert c.base_dn == "DC=sub,DC=corp,DC=local"


# ------------------------------------------------------------------
# Bug #1 fix: _search raises RuntimeError when conn is None
# ------------------------------------------------------------------

def test_search_raises_runtime_error_without_conn():
    """FIX #1: assert was stripped by python -O; must be an explicit RuntimeError."""
    c = make_collector()
    assert c.conn is None
    with pytest.raises(RuntimeError, match="connect()"):
        c._search("(objectClass=*)", ["cn"])


def test_search_does_not_raise_assertion_error():
    """Confirm the old AssertionError is no longer raised."""
    c = make_collector()
    with pytest.raises(RuntimeError):
        c._search("(objectClass=*)", ["cn"])
    # Should not be AssertionError
    try:
        c._search("(objectClass=*)", ["cn"])
    except RuntimeError:
        pass
    except AssertionError:
        pytest.fail("_search raised AssertionError — bug #1 not fixed")


# ------------------------------------------------------------------
# Bug #2 fix: userAccountControl cast handles None / list
# ------------------------------------------------------------------

def test_collect_users_handles_none_uac(mocker):
    """FIX #2: None UAC must not crash int() cast."""
    c = make_collector()
    c.conn = mocker.Mock()
    mocker.patch.object(c, "_search", return_value=[
        {"dn": "CN=ghost,DC=corp,DC=local",
         "sAMAccountName": "ghost",
         "userAccountControl": None,
         "servicePrincipalName": None},
    ])
    users = c.collect_users()
    assert users[0]["kerberoastable"] is False
    assert users[0]["asrep_roastable"] is False
    assert users[0]["disabled"] is False


def test_collect_users_handles_list_uac(mocker):
    """FIX #2: ldap3 may return UAC as single-element list."""
    c = make_collector()
    c.conn = mocker.Mock()
    mocker.patch.object(c, "_search", return_value=[
        {"dn": "CN=u1,DC=corp,DC=local",
         "sAMAccountName": "u1",
         "userAccountControl": [UAC_DONT_REQ_PREAUTH],
         "servicePrincipalName": None},
    ])
    users = c.collect_users()
    assert users[0]["asrep_roastable"] is True


# ------------------------------------------------------------------
# Kerberoastable / AS-REP flags
# ------------------------------------------------------------------

def test_collect_users_flags_kerberoastable(mocker):
    c = make_collector()
    c.conn = mocker.Mock()
    mocker.patch.object(c, "_search", return_value=[
        {"dn": "CN=jdoe,DC=corp,DC=local",
         "sAMAccountName": "jdoe",
         "userAccountControl": 512,
         "servicePrincipalName": ["HTTP/web01"]},
        {"dn": "CN=asvc,DC=corp,DC=local",
         "sAMAccountName": "asvc",
         "userAccountControl": UAC_DONT_REQ_PREAUTH,
         "servicePrincipalName": None},
    ])
    users = c.collect_users()
    assert users[0]["kerberoastable"] is True
    assert users[1]["asrep_roastable"] is True
    assert users[1]["disabled"] is False


# ------------------------------------------------------------------
# Bug #5 fix: UAC_NOT_DELEGATED is used in output
# ------------------------------------------------------------------

def test_collect_users_flags_not_delegatable(mocker):
    """FIX #5: UAC_NOT_DELEGATED should set not_delegatable=True."""
    c = make_collector()
    c.conn = mocker.Mock()
    mocker.patch.object(c, "_search", return_value=[
        {"dn": "CN=sensitive,DC=corp,DC=local",
         "sAMAccountName": "sensitive",
         "userAccountControl": UAC_NOT_DELEGATED,
         "servicePrincipalName": None},
    ])
    users = c.collect_users()
    assert users[0]["not_delegatable"] is True


# ------------------------------------------------------------------
# Computer flags
# ------------------------------------------------------------------

def test_collect_computers_flags_unconstrained_delegation(mocker):
    c = make_collector()
    c.conn = mocker.Mock()
    mocker.patch.object(c, "_search", return_value=[
        {"dn": "CN=SRV01,DC=corp,DC=local",
         "sAMAccountName": "SRV01$",
         "userAccountControl": UAC_TRUSTED_FOR_DELEGATION,
         "operatingSystem": "Windows Server 2019"},
    ])
    computers = c.collect_computers()
    assert computers[0]["unconstrained_delegation"] is True


# ------------------------------------------------------------------
# Bug #3 fix: collect_all unbinds even on exception
# ------------------------------------------------------------------

def test_collect_all_unbinds_on_exception(mocker):
    """FIX #3: LDAP socket must be unbound even if a collect_* method throws."""
    c = make_collector()
    mock_conn = mocker.Mock()
    mocker.patch.object(c, "connect", side_effect=lambda: setattr(c, "conn", mock_conn) or mock_conn)
    mocker.patch.object(c, "collect_users",    side_effect=RuntimeError("LDAP boom"))
    mocker.patch.object(c, "collect_groups",   return_value=[])
    mocker.patch.object(c, "collect_computers",return_value=[])
    mocker.patch.object(c, "collect_ous",      return_value=[])

    with pytest.raises(RuntimeError):
        c.collect_all()

    mock_conn.unbind.assert_called_once()


# ------------------------------------------------------------------
# JSON serialization
# ------------------------------------------------------------------

def test_collection_result_writes_json(tmp_path):
    result = CollectionResult(
        domain="corp.local",
        collected_at="2026-01-01T00:00:00Z",
        users=[{"dn": "u1"}],
    )
    out_path = result.to_json(tmp_path)
    assert out_path.exists()
    data = json.loads(out_path.read_text())
    assert data["domain"] == "corp.local"
    assert data["users"] == [{"dn": "u1"}]


def test_collection_result_json_filename(tmp_path):
    result = CollectionResult(domain="test.example.com", collected_at="x", users=[])
    out_path = result.to_json(tmp_path)
    assert "test.example.com" in out_path.name
