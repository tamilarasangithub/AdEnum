"""
Tests for GraphQueries — covers existing queries + bug fixes:
  - Bug #8: shortest_path now uses all relationship types (mock just verifies call)
  - Bug #11: dangerous_acls() exists and returns data
"""
from adenum.query import GraphQueries


def _make_gq(mocker):
    """Create a GraphQueries instance bypassing the real Neo4j driver."""
    gq          = GraphQueries.__new__(GraphQueries)
    mock_driver = mocker.Mock()
    mock_session = mocker.MagicMock()
    mock_session.__enter__.return_value = mock_session
    mock_session.__exit__.return_value  = False
    mock_driver.session.return_value    = mock_session
    gq.driver = mock_driver
    return gq, mock_session


def test_kerberoastable_users_calls_driver(mocker):
    gq, mock_session = _make_gq(mocker)
    mock_session.run.return_value = [
        mocker.Mock(data=lambda: {"name": "jdoe", "dn": "CN=jdoe,DC=corp,DC=local"})
    ]
    results = gq.kerberoastable_users()
    assert results == [{"name": "jdoe", "dn": "CN=jdoe,DC=corp,DC=local"}]
    mock_session.run.assert_called_once()


def test_asrep_roastable_users_calls_driver(mocker):
    gq, mock_session = _make_gq(mocker)
    mock_session.run.return_value = [
        mocker.Mock(data=lambda: {"name": "svc_noauth", "dn": "CN=svc,DC=corp,DC=local"})
    ]
    results = gq.asrep_roastable_users()
    assert len(results) == 1
    assert results[0]["name"] == "svc_noauth"


def test_unconstrained_delegation_hosts(mocker):
    gq, mock_session = _make_gq(mocker)
    mock_session.run.return_value = [
        mocker.Mock(data=lambda: {"name": "SRV01$", "os": "Windows Server 2019", "os_version": "10.0"})
    ]
    results = gq.unconstrained_delegation_hosts()
    assert results[0]["name"] == "SRV01$"


def test_shortest_path_passes_params(mocker):
    """FIX #8: confirm call is made (relationship types are in Cypher, not params)."""
    gq, mock_session = _make_gq(mocker)
    mock_session.run.return_value = []
    gq.shortest_path("jdoe", "Domain Admins")
    _, kwargs = mock_session.run.call_args
    assert kwargs["start"] == "jdoe"
    assert kwargs["end"]   == "Domain Admins"


def test_shortest_path_returns_empty_list_on_no_path(mocker):
    gq, mock_session = _make_gq(mocker)
    mock_session.run.return_value = []
    result = gq.shortest_path("nobody", "Domain Admins")
    assert result == []


def test_dangerous_acls_calls_driver(mocker):
    """FIX #11: dangerous_acls() method must exist and return rows."""
    gq, mock_session = _make_gq(mocker)
    mock_session.run.return_value = [
        mocker.Mock(data=lambda: {
            "source": "jdoe", "source_type": "User",
            "right":  "GenericAll",
            "target": "Domain Admins", "target_type": "Group",
        })
    ]
    results = gq.dangerous_acls()
    assert len(results) == 1
    assert results[0]["right"] == "GenericAll"
    mock_session.run.assert_called_once()


def test_dangerous_acls_returns_empty_on_no_findings(mocker):
    gq, mock_session = _make_gq(mocker)
    mock_session.run.return_value = []
    results = gq.dangerous_acls()
    assert results == []


def test_high_value_group_members(mocker):
    gq, mock_session = _make_gq(mocker)
    mock_session.run.return_value = [
        mocker.Mock(data=lambda: {"group": "Domain Admins", "members": ["Administrator", "jdoe"]})
    ]
    results = gq.high_value_group_members()
    assert results[0]["group"] == "Domain Admins"
    assert "jdoe" in results[0]["members"]


def test_full_graph_structure(mocker):
    """full_graph() must return a dict with 'nodes' and 'edges' keys."""
    gq, mock_session = _make_gq(mocker)
    # Two calls: one for nodes, one for edges
    mock_session.run.side_effect = [
        [mocker.Mock(data=lambda: {"id": 1, "label": "User", "name": "jdoe", "dn": "CN=jdoe,DC=corp,DC=local",
                                    "high_value": False, "disabled": False,
                                    "kerberoastable": True, "asrep_roastable": False,
                                    "unconstrained_delegation": False})],
        [mocker.Mock(data=lambda: {"from_id": 1, "to_id": 2, "type": "MemberOf"})],
    ]
    result = gq.full_graph()
    assert "nodes" in result
    assert "edges" in result
    assert result["nodes"][0]["name"] == "jdoe"
