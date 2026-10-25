import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any
from urllib.parse import quote

from CommonServerUserPython import *  # noqa: F401

""" CONSTANTS """

DEFAULT_API_PATH = "/api/v1"
DEFAULT_LIMIT = 50
MAX_LIMIT = 1000
ENTRY_TYPES = ["ip", "domain", "url"]
PRIORITIES = ["low", "medium", "high", "critical"]
ENTRY_STATUSES = ["active", "deleted", "all"]

# API field -> context key, for fields every request, entry, and denial has.
COMMON_FIELDS = {
    "entry": "Entry",
    "type": "Type",
    "status": "Status",
    "priority": "Priority",
    "justification": "Justification",
    "comment": "Comment",
    "servicenow_ticket": "ServiceNowTicket",
    "submitted_by": "SubmittedBy",
    "submitted_at": "SubmittedAt",
}
ENTRY_FIELDS = COMMON_FIELDS | {
    "id": "ID",
    "request_id": "RequestID",
    "approved_by": "ApprovedBy",
    "approved_at": "ApprovedAt",
    "approval_comment": "ApprovalComment",
    "deleted_by": "DeletedBy",
    "deleted_at": "DeletedAt",
    "deletion_reason": "DeletionReason",
}
DENIAL_FIELDS = COMMON_FIELDS | {
    "denied_by": "DeniedBy",
    "denied_at": "DeniedAt",
    "reason": "Reason",
}

REQUEST_HEADERS = ["ID", "Entry", "Type", "Status", "Priority", "ServiceNowTicket", "SubmittedBy", "SubmittedAt"]
ENTRY_HEADERS = ["ID", "Entry", "Type", "Status", "Priority", "ServiceNowTicket", "ApprovedBy", "ApprovedAt"]
REMOVED_HEADERS = ["ID", "Entry", "Type", "Status", "DeletedBy", "DeletedAt", "DeletionReason"]
# Column order for single-record views; empty columns are dropped.
REQUEST_DETAIL_HEADERS = [
    "ID",
    "Status",
    "Entry",
    "Type",
    "Priority",
    "Justification",
    "Comment",
    "ServiceNowTicket",
    "SubmittedBy",
    "SubmittedAt",
    "EntryID",
    "ApprovedBy",
    "ApprovedAt",
    "ApprovalComment",
    "DeniedBy",
    "DeniedAt",
    "Reason",
    "DeletedBy",
    "DeletedAt",
    "DeletionReason",
]
ENTRY_DETAIL_HEADERS = ["ID"] + [key for key in ENTRY_FIELDS.values() if key != "ID"]

""" CLIENT CLASS """


class Client(BaseClient):
    """Calls the EDL Manager REST API (version 1). Contains no XSOAR logic."""

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
        )

    @staticmethod
    def raise_api_error(response: requests.Response) -> None:
        """Turns an API error response into a DemistoException with the API's own message."""
        try:
            error = response.json().get("error") or {}
        except ValueError:
            error = {}
        code = error.get("code", "http_error")
        message = error.get("message") or response.text[:300]
        raise DemistoException(f"EDL Manager returned HTTP {response.status_code} ({code}): {message}", res=response)

    def request(self, method: str, url_suffix: str, **kwargs) -> dict[str, Any]:
        return self._http_request(method, url_suffix, error_handler=self.raise_api_error, **kwargs)

    def health(self) -> dict[str, Any]:
        return self.request("GET", "health")

    def submit_requests(self, body: dict[str, Any]) -> dict[str, Any]:
        """Returns {"created": [...], "skipped": [...]}. When every entry is skipped
        the API answers 422 "nothing_submitted"; that is returned as an empty
        "created" list rather than an error, so playbooks can carry on."""
        response = self._http_request("POST", "requests", json_data=body, ok_codes=(201, 422), resp_type="response")
        if response.status_code == 201:
            return response.json()["data"]
        error = response.json().get("error") or {}
        if error.get("code") == "nothing_submitted":
            return {"created": [], "skipped": error.get("skipped", [])}
        self.raise_api_error(response)
        return {}  # not reached

    def get_request(self, request_id: str) -> dict[str, Any]:
        return self.request("GET", f"requests/{quote(request_id, safe='')}")["data"]

    def list_requests(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.request("GET", "requests", params=params)

    def decide_request(self, request_id: str, decision: str, body: dict[str, Any]) -> dict[str, Any]:
        return self.request("POST", f"requests/{quote(request_id, safe='')}/{decision}", json_data=body)["data"]

    def list_entries(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.request("GET", "entries", params=params)

    def get_entry(self, entry_id: str) -> dict[str, Any]:
        return self.request("GET", f"entries/{quote(entry_id, safe='')}")["data"]

    def remove_entry(self, entry_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return self.request("DELETE", f"entries/{quote(entry_id, safe='')}", json_data=body)["data"]

    def get_metrics(self, days: int) -> dict[str, Any]:
        return self.request("GET", "metrics", params={"days": days})["data"]


""" HELPER FUNCTIONS """


def to_context(record: dict[str, Any], fields: dict[str, str]) -> dict[str, Any]:
    """Maps API fields to context keys, leaving out empty values."""
    return {key: record[field] for field, key in fields.items() if record.get(field) not in (None, "")}


def request_context(request_id: str, status: str, record: dict[str, Any]) -> dict[str, Any]:
    """Context for a request wherever it is now: pending (record is the request),
    approved or deleted (record is the blocklist entry), or denied (record is the denial)."""
    if status == "denied":
        context = to_context(record, DENIAL_FIELDS)
    elif status in ("approved", "deleted"):
        context = to_context(record, ENTRY_FIELDS)
        context["EntryID"] = context.pop("ID", None)
        context.pop("RequestID", None)
    else:
        context = to_context(record, COMMON_FIELDS)
    return {"ID": request_id, **context, "Status": status}


def camelize_keys(value: Any) -> Any:
    """Converts snake_case keys to CamelCase at every level (createContext only does the top level)."""
    if isinstance(value, dict):
        return {underscoreToCamelCase(key): camelize_keys(item) for key, item in value.items()}
    if isinstance(value, list):
        return [camelize_keys(item) for item in value]
    return value


def page_params(args: dict[str, Any]) -> dict[str, Any]:
    limit = arg_to_number(args.get("limit"), arg_name="limit")
    offset = arg_to_number(args.get("offset"), arg_name="offset")
    limit = DEFAULT_LIMIT if limit is None else limit
    offset = 0 if offset is None else offset
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")
    if offset < 0:
        raise ValueError("offset must be 0 or more")
    return {"limit": limit, "offset": offset}


def check_choice(value: str | None, name: str, choices: list[str]) -> str | None:
    if value and value not in choices:
        raise ValueError(f"{name} must be one of: {', '.join(choices)}")
    return value or None


def page_note(response: dict[str, Any]) -> str:
    shown = len(response["data"])
    return f"Showing {shown} of {response['total']} (offset {response['offset']})."


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Checks that the server answers and the API key can read requests."""
    client.health()
    try:
        client.list_requests({"limit": 1})
    except DemistoException as e:
        if e.res is not None and e.res.status_code == 401:
            return "Authorization error: check the API key."
        if e.res is not None and e.res.status_code == 403:
            return "The API key needs the view permission."
        raise
    return "ok"


def request_submit_command(client: Client, args: dict[str, Any]) -> CommandResults:
    entries = argToList(args.get("entries"))
    if not entries:
        raise ValueError("Provide at least one entry")
    body = assign_params(
        entries=entries,
        type=check_choice(args.get("type"), "type", ENTRY_TYPES),
        justification=args.get("justification"),
        servicenow_ticket=args.get("servicenow_ticket"),
        priority=check_choice(args.get("priority"), "priority", PRIORITIES),
        comment=args.get("comment"),
    )
    result = client.submit_requests(body)

    created = [request_context(request["id"], request["status"], request) for request in result["created"]]
    skipped = [{"Entry": item["entry"], "Reason": item["reason"]} for item in result["skipped"]]
    readable = tableToMarkdown(f"Submitted {len(created)} of {len(entries)} entries for approval", created, REQUEST_HEADERS)
    if skipped:
        readable += tableToMarkdown("Skipped", skipped, ["Entry", "Reason"])

    outputs: dict[str, Any] = {}
    if created:
        outputs["EDLManager.Request(val.ID && val.ID == obj.ID)"] = created
    if skipped:
        outputs["EDLManager.SkippedEntry"] = skipped
    return CommandResults(outputs=outputs or None, readable_output=readable, raw_response=result)


def request_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    request_id = args["request_id"]
    result = client.get_request(request_id)
    context = request_context(result["request_id"], result["status"], result["record"])
    return CommandResults(
        outputs_prefix="EDLManager.Request",
        outputs_key_field="ID",
        outputs=context,
        readable_output=tableToMarkdown(f"EDL Manager request {request_id}", context, REQUEST_DETAIL_HEADERS, removeNull=True),
        raw_response=result,
    )


def request_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    params = page_params(args) | assign_params(
        type=check_choice(args.get("type"), "type", ENTRY_TYPES),
        q=args.get("query"),
    )
    response = client.list_requests(params)
    requests_context = [request_context(request["id"], request["status"], request) for request in response["data"]]
    return CommandResults(
        outputs_prefix="EDLManager.Request",
        outputs_key_field="ID",
        outputs=requests_context,
        readable_output=tableToMarkdown("Pending EDL Manager requests", requests_context, REQUEST_HEADERS) + page_note(response),
        raw_response=response,
    )


def request_approve_command(client: Client, args: dict[str, Any]) -> CommandResults:
    entry = client.decide_request(args["request_id"], "approve", assign_params(comment=args.get("comment")))
    context = to_context(entry, ENTRY_FIELDS)
    return CommandResults(
        outputs_prefix="EDLManager.Entry",
        outputs_key_field="ID",
        outputs=context,
        readable_output=tableToMarkdown(
            f"Approved: {entry['entry']} is on the {entry['type']} blocklist", context, ENTRY_HEADERS
        ),
        raw_response=entry,
    )


def request_deny_command(client: Client, args: dict[str, Any]) -> CommandResults:
    denial = client.decide_request(args["request_id"], "deny", {"reason": args["reason"]})
    context = request_context(denial["request_id"], "denied", denial)
    return CommandResults(
        outputs_prefix="EDLManager.Request",
        outputs_key_field="ID",
        outputs=context,
        readable_output=tableToMarkdown(f"Denied: {denial['entry']}", context, REQUEST_HEADERS + ["Reason"]),
        raw_response=denial,
    )


def entry_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    params = page_params(args) | assign_params(
        status=check_choice(args.get("status"), "status", ENTRY_STATUSES),
        type=check_choice(args.get("type"), "type", ENTRY_TYPES),
        q=args.get("query"),
    )
    response = client.list_entries(params)
    entries = [to_context(entry, ENTRY_FIELDS) for entry in response["data"]]
    return CommandResults(
        outputs_prefix="EDLManager.Entry",
        outputs_key_field="ID",
        outputs=entries,
        readable_output=tableToMarkdown("EDL Manager blocklist entries", entries, ENTRY_HEADERS) + page_note(response),
        raw_response=response,
    )


def entry_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    entry = client.get_entry(args["entry_id"])
    context = to_context(entry, ENTRY_FIELDS)
    return CommandResults(
        outputs_prefix="EDLManager.Entry",
        outputs_key_field="ID",
        outputs=context,
        readable_output=tableToMarkdown(f"EDL Manager entry {entry['entry']}", context, ENTRY_DETAIL_HEADERS, removeNull=True),
        raw_response=entry,
    )


def entry_remove_command(client: Client, args: dict[str, Any]) -> CommandResults:
    entry = client.remove_entry(args["entry_id"], assign_params(reason=args.get("reason")))
    context = to_context(entry, ENTRY_FIELDS)
    return CommandResults(
        outputs_prefix="EDLManager.Entry",
        outputs_key_field="ID",
        outputs=context,
        readable_output=tableToMarkdown(f"Removed {entry['entry']} from the {entry['type']} blocklist", context, REMOVED_HEADERS),
        raw_response=entry,
    )


def metrics_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    days = arg_to_number(args.get("days"), arg_name="days")
    days = 30 if days is None else days
    if not 1 <= days <= 3650:
        raise ValueError("days must be between 1 and 3650")
    metrics = client.get_metrics(days)
    numbers = {
        "Blocked Now": metrics["indicators"]["active"]["total"],
        "Approved": metrics["requests"]["approved"],
        "Denied": metrics["requests"]["denied"],
        "Pending": metrics["requests"]["pending"],
        "Median Request To Approval (s)": metrics["time_to_block"]["median_seconds"],
        "Median Approval To Firewall (s)": metrics["time_to_enforcement"]["median_seconds"],
        "Firewall Clients Polling": metrics["firewalls"]["polling"],
        "Firewall Clients Stopped": metrics["firewalls"]["stale"],
    }
    readable = "### EDL Manager impact, last {} days\n{}\n\n{}".format(
        days,
        "\n".join(f"- {line}" for line in metrics["summary"]),
        tableToMarkdown("Key numbers", numbers, list(numbers), removeNull=True),
    )
    return CommandResults(
        outputs_prefix="EDLManager.Metrics",
        outputs=camelize_keys(metrics),
        readable_output=readable,
        raw_response=metrics,
    )


""" MAIN FUNCTION """

COMMANDS = {
    "edl-manager-request-submit": request_submit_command,
    "edl-manager-request-get": request_get_command,
    "edl-manager-request-list": request_list_command,
    "edl-manager-request-approve": request_approve_command,
    "edl-manager-request-deny": request_deny_command,
    "edl-manager-entry-list": entry_list_command,
    "edl-manager-entry-get": entry_get_command,
    "edl-manager-entry-remove": entry_remove_command,
    "edl-manager-metrics-get": metrics_get_command,
}


def main() -> None:  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        api_path = "/" + (params.get("api_path") or DEFAULT_API_PATH).strip("/")
        client = Client(
            base_url=params["url"].rstrip("/") + api_path,
            api_key=params.get("credentials", {}).get("password", ""),
            verify=not argToBoolean(params.get("insecure", False)),
            proxy=argToBoolean(params.get("proxy", False)),
        )
        if command == "test-module":
            return_results(test_module(client))
        elif command in COMMANDS:
            return_results(COMMANDS[command](client, demisto.args()))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
