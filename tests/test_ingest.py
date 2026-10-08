"""
Tests for GraphIngestor — covers bug fixes from the audit:
  - Bug #6: _link_members() handles None from result.single() without crash
  - Bug #7: create_indexes() is called during ingest_file()
"""
import json

from adenum.ingest import GraphIngestor


def _make_ingestor(mocker):
    """Create GraphIngestor bypassing the real Neo4j driver."""
    ingestor      = GraphIngestor.__new__(GraphIngestor)
    mock_driver   = mocker.Mock()
    mock_session  = mocker.MagicMock()
    mock_session.__enter__.return_value = mock_session
    mock_session.__exit__.return_value  = False
    mock_driver.session.return_value    = mock_session
    ingestor.driver = mock_driver
    return ingestor, mock_driver, mock_session


# ------------------------------------------------------------------
# Bug #7: create_indexes is called during ingest_file
# ------------------------------------------------------------------

def test_create_indexes_called_on_ingest(mocker, tmp_path):
    """FIX #7: Uniqueness constraints must be created before MERGE calls."""
    ingestor, _mock_driver, _mock_session = _make_ingestor(mocker)
    mocker.patch.object(ingestor, "create_indexes")

    # Provide a minimal JSON file
    data = {"users": [], "groups": [], "computers": [], "ous": []}
    json_file = tmp_path / "test.json"
    json_file.write_text(json.dumps(data))

    ingestor.ingest_file(json_file)
    ingestor.create_indexes.assert_called_once()


def test_create_indexes_runs_four_constraints(mocker):
    """FIX #7: Four CONSTRAINT statements — one per label."""
    ingestor, _mock_driver, mock_session = _make_ingestor(mocker)

    ingestor.create_indexes()

    # session() is called once inside create_indexes
    assert mock_session.run.call_count == 4
    cypher_calls = [str(c.args[0]) for c in mock_session.run.call_args_list]
    labels = ["User", "Group", "Computer", "OU"]
    for label in labels:
        assert any(label in c for c in cypher_calls), f"Missing constraint for {label}"


# ------------------------------------------------------------------
# Bug #6: _link_members handles None from result.single()
# ------------------------------------------------------------------

def test_link_members_handles_none_single(mocker):
    """FIX #6: single() returns None when MATCH finds no rows — must not crash."""
    ingestor, _, _ = _make_ingestor(mocker)

    tx     = mocker.Mock()
    result = mocker.Mock()
    result.single.return_value = None      # simulate no matching node
    tx.run.return_value = result

    group = {
        "dn":     "CN=TestGroup,DC=corp,DC=local",
        "member": ["CN=nobody,DC=corp,DC=local"],
    }
    # Should not raise TypeError
    count = ingestor._link_members(tx, group)
    assert count == 0


def test_link_members_counts_correctly(mocker):
    """_link_members returns correct edge count when nodes exist."""
    ingestor, _, _ = _make_ingestor(mocker)

    tx     = mocker.Mock()
    result = mocker.Mock()
    result.single.return_value = {"c": 1}
    tx.run.return_value = result

    group = {
        "dn":     "CN=DA,DC=corp,DC=local",
        "member": ["CN=u1,DC=corp,DC=local", "CN=u2,DC=corp,DC=local"],
    }
    count = ingestor._link_members(tx, group)
    assert count == 2


def test_link_members_handles_string_member(mocker):
    """_link_members must handle single string value (not list) for 'member'."""
    ingestor, _, _ = _make_ingestor(mocker)

    tx     = mocker.Mock()
    result = mocker.Mock()
    result.single.return_value = {"c": 1}
    tx.run.return_value = result

    group = {
        "dn":     "CN=DA,DC=corp,DC=local",
        "member": "CN=u1,DC=corp,DC=local",   # single string, not list
    }
    count = ingestor._link_members(tx, group)
    assert count == 1


def test_link_members_handles_empty_members(mocker):
    """_link_members with no members returns 0 and makes no DB calls."""
    ingestor, _, _ = _make_ingestor(mocker)
    tx = mocker.Mock()

    group = {"dn": "CN=Empty,DC=corp,DC=local", "member": None}
    count = ingestor._link_members(tx, group)
    assert count == 0
    tx.run.assert_not_called()


# ------------------------------------------------------------------
# Ingest stats
# ------------------------------------------------------------------

def test_ingest_file_returns_correct_stats(mocker, tmp_path):
    """ingest_file should count users/groups/computers/ous correctly."""
    ingestor, _mock_driver, mock_session = _make_ingestor(mocker)
    mocker.patch.object(ingestor, "create_indexes")
    mock_session.execute_write.return_value = 0  # _link_members returns 0

    data = {
        "users":     [{"dn": "CN=u1,DC=corp,DC=local", "sAMAccountName": "u1"}],
        "groups":    [{"dn": "CN=g1,DC=corp,DC=local", "sAMAccountName": "g1", "member": []}],
        "computers": [{"dn": "CN=c1,DC=corp,DC=local", "sAMAccountName": "c1$"}],
        "ous":       [{"dn": "OU=Users,DC=corp,DC=local", "ou": "Users"}],
    }
    json_file = tmp_path / "data.json"
    json_file.write_text(json.dumps(data))

    stats = ingestor.ingest_file(json_file)
    assert stats["users"]     == 1
    assert stats["groups"]    == 1
    assert stats["computers"] == 1
    assert stats["ous"]       == 1
