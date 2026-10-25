"""Unit tests for the EDL Manager integration.

The test_data files are real responses from the EDL Manager REST API.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from CommonServerPython import DemistoException
from EDLManager import (
    Client,
    entry_get_command,
    entry_list_command,
    entry_remove_command,
    metrics_get_command,
    request_approve_command,
    request_deny_command,
    request_get_command,
    request_list_command,
    request_submit_command,
)
from EDLManager import test_module as run_test_module

BASE_URL = "https://edl.example.com/api/v1"
TEST_DATA = Path(__file__).parent / "test_data"


def load(name: str) -> dict[str, Any]:
    return json.loads((TEST_DATA / f"{name}.json").read_text())


@pytest.fixture
def client() -> Client:
    return Client(base_url=BASE_URL, api_key="edl_test_key", verify=False, proxy=False)


def test_requests_send_the_api_key(client, requests_mock):
    """Given an API key, when a command runs, then it is sent as a bearer token."""
    mock = requests_mock.get(f"{BASE_URL}/requests", json=load("request_list"))
    request_list_command(client, {})
    assert mock.last_request.headers["Authorization"] == "Bearer edl_test_key"


def test_submit_creates_requests_and_lists_skipped_entries(client, requests_mock):
    """Given four entries, one invalid, when submitted, then three requests are created and one is skipped."""
    mock = requests_mock.post(f"{BASE_URL}/requests", json=load("request_submit"), status_code=201)
    result = request_submit_command(
        client,
        {
            "entries": "198.51.100.7,evil.example.com,https://bad.example.net/login,not valid!",
            "justification": "C2 infrastructure from incident 1234",
            "servicenow_ticket": "SIR0012345",
            "priority": "high",
        },
    )

    assert mock.last_request.json() == {
        "entries": ["198.51.100.7", "evil.example.com", "https://bad.example.net/login", "not valid!"],
        "justification": "C2 infrastructure from incident 1234",
        "servicenow_ticket": "SIR0012345",
        "priority": "high",
    }
    created = result.outputs["EDLManager.Request(val.ID && val.ID == obj.ID)"]
    assert [request["Entry"] for request in created] == ["198.51.100.7", "evil.example.com", "https://bad.example.net/login"]
    assert {request["Status"] for request in created} == {"pending"}
    assert created[0]["SubmittedBy"] == "api:xsoar"
    assert result.outputs["EDLManager.SkippedEntry"] == [
        {"Entry": "not valid!", "Reason": 'Could not determine the entry type; pass "type" (ip, domain, or url)'}
    ]
    assert "Submitted 3 of 4 entries" in result.readable_output
    assert "Skipped" in result.readable_output


def test_submit_with_nothing_new_returns_the_skipped_entries(client, requests_mock):
    """Given only an entry that is already pending, when submitted, then no error is raised and the reason is returned."""
    requests_mock.post(f"{BASE_URL}/requests", json=load("request_submit_nothing"), status_code=422)
    result = request_submit_command(
        client, {"entries": "198.51.100.7", "justification": "again", "servicenow_ticket": "SIR0012345"}
    )
    assert "EDLManager.Request(val.ID && val.ID == obj.ID)" not in result.outputs
    assert result.outputs["EDLManager.SkippedEntry"] == [{"Entry": "198.51.100.7", "Reason": "Already pending approval"}]
    assert "Submitted 0 of 1 entries" in result.readable_output


def test_submit_validation_error_raises_the_api_message(client, requests_mock):
    """Given a malformed ticket, when submitted, then the API's validation message is raised."""
    requests_mock.post(f"{BASE_URL}/requests", json=load("request_submit_invalid"), status_code=422)
    with pytest.raises(DemistoException, match="HTTP 422 \\(validation_failed\\): justification is required"):
        request_submit_command(client, {"entries": "198.51.100.8", "servicenow_ticket": "BAD"})


@pytest.mark.parametrize(
    "args, message",
    [
        ({"entries": ""}, "at least one entry"),
        ({"entries": "198.51.100.7", "type": "hash"}, "type must be one of"),
        ({"entries": "198.51.100.7", "priority": "urgent"}, "priority must be one of"),
    ],
)
def test_submit_rejects_invalid_arguments(client, args, message):
    """Given invalid arguments, when submitted, then nothing is sent and a clear error is raised."""
    with pytest.raises(ValueError, match=message):
        request_submit_command(client, args)


def test_request_get_pending(client, requests_mock):
    """Given a pending request, when fetched, then its status is pending."""
    data = load("request_get_pending")
    requests_mock.get(f"{BASE_URL}/requests/{data['data']['request_id']}", json=data)
    result = request_get_command(client, {"request_id": data["data"]["request_id"]})
    assert result.outputs["ID"] == data["data"]["request_id"]
    assert result.outputs["Status"] == "pending"
    assert result.outputs["Entry"] == "https://bad.example.net/login"
    assert "EntryID" not in result.outputs


def test_request_get_approved_then_removed_includes_the_entry_id(client, requests_mock):
    """Given a request approved and later removed, when fetched, then the status is deleted and EntryID is set."""
    data = load("request_get_approved")
    request_id = data["data"]["request_id"]
    requests_mock.get(f"{BASE_URL}/requests/{request_id}", json=data)
    result = request_get_command(client, {"request_id": request_id})
    assert result.outputs["ID"] == request_id
    assert result.outputs["Status"] == data["data"]["status"]
    assert result.outputs["EntryID"] == data["data"]["record"]["id"]
    assert result.outputs["ApprovedBy"] == "api:xsoar"
    assert "RequestID" not in result.outputs


def test_request_get_denied_includes_the_reason(client, requests_mock):
    """Given a denied request, when fetched, then the denial reason is returned."""
    data = load("request_get_denied")
    request_id = data["data"]["request_id"]
    requests_mock.get(f"{BASE_URL}/requests/{request_id}", json=data)
    result = request_get_command(client, {"request_id": request_id})
    assert result.outputs["ID"] == request_id
    assert result.outputs["Status"] == "denied"
    assert result.outputs["Reason"] == "False positive"


def test_request_ids_are_escaped(client, requests_mock):
    """Given an ID with a slash, when fetched, then it is sent as one path segment."""
    mock = requests_mock.get(f"{BASE_URL}/requests/a%2Fb", json=load("request_get_pending"))
    request_get_command(client, {"request_id": "a/b"})
    assert mock.called


def test_request_list_passes_filters_and_paging(client, requests_mock):
    """Given filters, when listing requests, then they are sent as query parameters."""
    mock = requests_mock.get(f"{BASE_URL}/requests", json=load("request_list"))
    result = request_list_command(client, {"type": "url", "query": "bad", "limit": "10", "offset": "5"})
    assert mock.last_request.qs == {"limit": ["10"], "offset": ["5"], "type": ["url"], "q": ["bad"]}
    assert len(result.outputs) == len(load("request_list")["data"])
    assert result.outputs[0]["Status"] == "pending"
    assert "Showing 3 of 3" in result.readable_output


@pytest.mark.parametrize("args", [{"limit": "0"}, {"limit": "1001"}, {"offset": "-1"}])
def test_list_paging_is_validated(client, args):
    with pytest.raises(ValueError):
        request_list_command(client, args)


def test_request_approve(client, requests_mock):
    """Given a pending request, when approved, then the comment is sent and the new entry is returned."""
    data = load("request_approve")
    request_id = data["data"]["request_id"]
    mock = requests_mock.post(f"{BASE_URL}/requests/{request_id}/approve", json=data)
    result = request_approve_command(client, {"request_id": request_id, "comment": "Confirmed C2"})
    assert mock.last_request.json() == {"comment": "Confirmed C2"}
    assert result.outputs_prefix == "EDLManager.Entry"
    assert result.outputs["ID"] == data["data"]["id"]
    assert result.outputs["RequestID"] == request_id
    assert result.outputs["Status"] == "active"
    assert "Approved: 198.51.100.7 is on the ip blocklist" in result.readable_output


def test_request_approve_conflict_raises(client, requests_mock):
    """Given an already decided request, when approved, then the API's conflict message is raised."""
    requests_mock.post(f"{BASE_URL}/requests/req_1/approve", json=load("error_conflict"), status_code=409)
    with pytest.raises(DemistoException, match="HTTP 409 \\(conflict\\): Request was already deleted"):
        request_approve_command(client, {"request_id": "req_1"})


def test_request_deny(client, requests_mock):
    """Given a pending request, when denied, then the reason is sent and the request shows as denied."""
    data = load("request_deny")
    request_id = data["data"]["request_id"]
    mock = requests_mock.post(f"{BASE_URL}/requests/{request_id}/deny", json=data)
    result = request_deny_command(client, {"request_id": request_id, "reason": "False positive"})
    assert mock.last_request.json() == {"reason": "False positive"}
    assert result.outputs["ID"] == request_id
    assert result.outputs["Status"] == "denied"
    assert result.outputs["DeniedBy"] == "api:xsoar"


def test_entry_list(client, requests_mock):
    """Given filters, when listing entries, then they are sent and the entries are returned."""
    mock = requests_mock.get(f"{BASE_URL}/entries", json=load("entry_list"))
    result = entry_list_command(client, {"status": "all", "type": "ip"})
    assert mock.last_request.qs == {"limit": ["50"], "offset": ["0"], "status": ["all"], "type": ["ip"]}
    assert result.outputs[0]["Entry"] == "198.51.100.7"


def test_entry_list_rejects_unknown_status(client):
    with pytest.raises(ValueError, match="status must be one of"):
        entry_list_command(client, {"status": "removed"})


def test_entry_get(client, requests_mock):
    data = load("entry_get")
    requests_mock.get(f"{BASE_URL}/entries/{data['data']['id']}", json=data)
    result = entry_get_command(client, {"entry_id": data["data"]["id"]})
    assert result.outputs["ID"] == data["data"]["id"]
    assert result.outputs["ApprovalComment"] == "Confirmed C2"


def test_entry_remove(client, requests_mock):
    """Given an active entry, when removed, then the reason is sent and the entry shows as deleted."""
    data = load("entry_remove")
    mock = requests_mock.delete(f"{BASE_URL}/entries/{data['data']['id']}", json=data)
    result = entry_remove_command(client, {"entry_id": data["data"]["id"], "reason": "Incident closed"})
    assert mock.last_request.json() == {"reason": "Incident closed"}
    assert result.outputs["Status"] == "deleted"
    assert result.outputs["DeletionReason"] == "Incident closed"


def test_not_found_raises_the_api_message(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/requests/req_missing", json=load("error_not_found"), status_code=404)
    with pytest.raises(DemistoException, match="HTTP 404 \\(not_found\\): Request not found"):
        request_get_command(client, {"request_id": "req_missing"})


def test_non_json_errors_are_reported(client, requests_mock):
    """Given a proxy error page, when a command runs, then the status and body are reported."""
    requests_mock.get(f"{BASE_URL}/entries/app_1", text="<html>Bad Gateway</html>", status_code=502)
    with pytest.raises(DemistoException, match="HTTP 502 \\(http_error\\): <html>Bad Gateway</html>"):
        entry_get_command(client, {"entry_id": "app_1"})


def test_metrics_converts_keys_and_summarizes(client, requests_mock):
    """Given metrics, when fetched, then nested keys are CamelCase and the summary is shown."""
    data = load("metrics_get")
    mock = requests_mock.get(f"{BASE_URL}/metrics", json=data)
    result = metrics_get_command(client, {"days": "30"})
    assert mock.last_request.qs == {"days": ["30"]}
    assert result.outputs["Indicators"]["Active"]["Total"] == data["data"]["indicators"]["active"]["total"]
    assert result.outputs["TimeToBlock"]["MedianSeconds"] == data["data"]["time_to_block"]["median_seconds"]
    assert result.outputs["Firewalls"]["Clients"][0]["UserAgent"] == "PAN-OS 11.1"
    assert data["data"]["summary"][0] in result.readable_output


def test_metrics_days_are_validated(client):
    with pytest.raises(ValueError, match="days must be between"):
        metrics_get_command(client, {"days": "0"})


def test_test_module_ok(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/health", json={"status": "ok", "version": "2.1.0"})
    requests_mock.get(f"{BASE_URL}/requests", json=load("request_list"))
    assert run_test_module(client) == "ok"


@pytest.mark.parametrize(
    "status, body, expected",
    [
        (401, load("error_unauthorized"), "Authorization error: check the API key."),
        (
            403,
            {"error": {"code": "forbidden", "message": 'This API key lacks the "view" permission'}},
            "The API key needs the view permission.",
        ),
    ],
)
def test_test_module_explains_key_problems(client, requests_mock, status, body, expected):
    requests_mock.get(f"{BASE_URL}/health", json={"status": "ok", "version": "2.1.0"})
    requests_mock.get(f"{BASE_URL}/requests", json=body, status_code=status)
    assert run_test_module(client) == expected
