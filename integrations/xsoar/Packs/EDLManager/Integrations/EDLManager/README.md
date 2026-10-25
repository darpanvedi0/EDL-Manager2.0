Submit IP addresses, domains, and URLs for approval in EDL Manager and track them until they are published to the External Dynamic Lists your firewalls fetch.
This integration was integrated and tested with EDL Manager 2.1 (REST API v1).

## Configure EDL Manager in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., https://edl.example.com) |  | True |
| API Key | Create the key in EDL Manager on the API Keys page of the Admin menu. Give it the permissions the commands you use need: view, submit, approve, remove. | True |
| API path | Use /api/v1/index.php if the web server doesn't route /api/v1/\* to the API. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### edl-manager-request-submit

***
Submits entries for approval. Once approved, each entry is published to the blocklist for its type. Entries that are invalid, already blocked, already pending, or previously denied are skipped and listed with the reason. Entries containing & < > " or ' are not supported. The API key needs the submit permission.

#### Base Command

`edl-manager-request-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entries | IP addresses, CIDR ranges, domains, or http(s) URLs to block, comma-separated. Up to 500. | Required | 
| type | The type of every entry. When not set, the type of each entry is detected. Possible values are: ip, domain, url. | Optional | 
| justification | Why the entries should be blocked. | Required | 
| servicenow_ticket | The ServiceNow ticket for the request: INC, REQ, CHG, RITM, TASK, SCTASK, or SIR followed by 7 digits, for example SIR0012345. | Required | 
| priority | The request priority. Possible values are: low, medium, high, critical. Default is medium. | Optional | 
| comment | An additional comment for the approver. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EDLManager.Request.ID | String | The request ID. | 
| EDLManager.Request.Entry | String | The IP address, CIDR range, domain, or URL. | 
| EDLManager.Request.Type | String | The entry type: ip, domain, or url. | 
| EDLManager.Request.Status | String | Where the request is now: pending, approved, denied, or deleted \(approved, then removed from the blocklist\). | 
| EDLManager.Request.Priority | String | The priority: low, medium, high, or critical. | 
| EDLManager.Request.Justification | String | Why the entry should be blocked. | 
| EDLManager.Request.Comment | String | An additional comment from the submitter. | 
| EDLManager.Request.ServiceNowTicket | String | The ServiceNow ticket for the request. | 
| EDLManager.Request.SubmittedBy | String | Who submitted the request. Submissions through the API show as api:&lt;key name&gt;. | 
| EDLManager.Request.SubmittedAt | Date | When the request was submitted. | 
| EDLManager.SkippedEntry.Entry | String | An entry that was not submitted. | 
| EDLManager.SkippedEntry.Reason | String | Why it was not submitted, for example "Already in the blocklist". | 

#### Command example
```!edl-manager-request-submit entries="203.0.113.10,phish.example.org,https://login.example.net/verify,999.1.1.1" justification="Phishing campaign from incident 4821" servicenow_ticket=SIR0004821 priority=high```
#### Context Example
```json
{
    "EDLManager": {
        "Request": [
            {
                "ID": "req_6add186a31eef_5286cdde",
                "Entry": "203.0.113.10",
                "Type": "ip",
                "Status": "pending",
                "Priority": "high",
                "Justification": "Phishing campaign from incident 4821",
                "ServiceNowTicket": "SIR0004821",
                "SubmittedBy": "api:xsoar-prod",
                "SubmittedAt": "2026-10-24T20:43:22+00:00"
            },
            {
                "ID": "req_6add186a31f3e_670eff31",
                "Entry": "phish.example.org",
                "Type": "domain",
                "Status": "pending",
                "Priority": "high",
                "Justification": "Phishing campaign from incident 4821",
                "ServiceNowTicket": "SIR0004821",
                "SubmittedBy": "api:xsoar-prod",
                "SubmittedAt": "2026-10-24T20:43:22+00:00"
            },
            {
                "ID": "req_6add186a31f47_29b66601",
                "Entry": "https://login.example.net/verify",
                "Type": "url",
                "Status": "pending",
                "Priority": "high",
                "Justification": "Phishing campaign from incident 4821",
                "ServiceNowTicket": "SIR0004821",
                "SubmittedBy": "api:xsoar-prod",
                "SubmittedAt": "2026-10-24T20:43:22+00:00"
            }
        ],
        "SkippedEntry": [
            {
                "Entry": "999.1.1.1",
                "Reason": "Could not determine the entry type; pass \"type\" (ip, domain, or url)"
            }
        ]
    }
}
```

#### Human Readable Output

>### Submitted 3 of 4 entries for approval
>|ID|Entry|Type|Status|Priority|ServiceNowTicket|SubmittedBy|SubmittedAt|
>|---|---|---|---|---|---|---|---|
>| req_6add186a31eef_5286cdde | 203.0.113.10 | ip | pending | high | SIR0004821 | api:xsoar-prod | 2026-10-24T20:43:22+00:00 |
>| req_6add186a31f3e_670eff31 | phish.example.org | domain | pending | high | SIR0004821 | api:xsoar-prod | 2026-10-24T20:43:22+00:00 |
>| req_6add186a31f47_29b66601 | https://login.example.net/verify | url | pending | high | SIR0004821 | api:xsoar-prod | 2026-10-24T20:43:22+00:00 |
>### Skipped
>|Entry|Reason|
>|---|---|
>| 999.1.1.1 | Could not determine the entry type; pass "type" (ip, domain, or url) |

### edl-manager-request-get

***
Gets a request and where it is now: pending, approved, denied, or deleted (approved, then removed). Use it to poll for the approver's decision. The API key needs the view permission.

#### Base Command

`edl-manager-request-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The request ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EDLManager.Request.ID | String | The request ID. | 
| EDLManager.Request.Entry | String | The IP address, CIDR range, domain, or URL. | 
| EDLManager.Request.Type | String | The entry type: ip, domain, or url. | 
| EDLManager.Request.Status | String | Where the request is now: pending, approved, denied, or deleted \(approved, then removed from the blocklist\). | 
| EDLManager.Request.Priority | String | The priority: low, medium, high, or critical. | 
| EDLManager.Request.Justification | String | Why the entry should be blocked. | 
| EDLManager.Request.Comment | String | An additional comment from the submitter. | 
| EDLManager.Request.ServiceNowTicket | String | The ServiceNow ticket for the request. | 
| EDLManager.Request.SubmittedBy | String | Who submitted the request. Submissions through the API show as api:&lt;key name&gt;. | 
| EDLManager.Request.SubmittedAt | Date | When the request was submitted. | 
| EDLManager.Request.EntryID | String | The blocklist entry ID, once the request is approved. | 
| EDLManager.Request.ApprovedBy | String | Who approved the request. | 
| EDLManager.Request.ApprovedAt | Date | When the request was approved. | 
| EDLManager.Request.ApprovalComment | String | The approver's comment. | 
| EDLManager.Request.DeniedBy | String | Who denied the request. | 
| EDLManager.Request.DeniedAt | Date | When the request was denied. | 
| EDLManager.Request.Reason | String | Why the request was denied. | 
| EDLManager.Request.DeletedBy | String | Who removed the approved entry from the blocklist. | 
| EDLManager.Request.DeletedAt | Date | When the approved entry was removed from the blocklist. | 
| EDLManager.Request.DeletionReason | String | Why the approved entry was removed. | 

#### Command example
```!edl-manager-request-get request_id=req_6add186a31eef_5286cdde```
#### Context Example
```json
{
    "EDLManager": {
        "Request": {
            "ID": "req_6add186a31eef_5286cdde",
            "Entry": "203.0.113.10",
            "Type": "ip",
            "Status": "approved",
            "Priority": "high",
            "Justification": "Phishing campaign from incident 4821",
            "ServiceNowTicket": "SIR0004821",
            "SubmittedBy": "api:xsoar-prod",
            "SubmittedAt": "2026-10-24T20:43:22+00:00",
            "ApprovedBy": "api:xsoar-prod",
            "ApprovedAt": "2026-10-24T20:43:22+00:00",
            "ApprovalComment": "Confirmed phishing infrastructure",
            "EntryID": "app_6add186a364336.19620368"
        }
    }
}
```

#### Human Readable Output

>### EDL Manager request req_6add186a31eef_5286cdde
>|ID|Status|Entry|Type|Priority|Justification|ServiceNowTicket|SubmittedBy|SubmittedAt|EntryID|ApprovedBy|ApprovedAt|ApprovalComment|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| req_6add186a31eef_5286cdde | approved | 203.0.113.10 | ip | high | Phishing campaign from incident 4821 | SIR0004821 | api:xsoar-prod | 2026-10-24T20:43:22+00:00 | app_6add186a364336.19620368 | api:xsoar-prod | 2026-10-24T20:43:22+00:00 | Confirmed phishing infrastructure |

### edl-manager-request-list

***
Lists pending requests, newest first. The API key needs the view permission.

#### Base Command

`edl-manager-request-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Only requests of this type. Possible values are: ip, domain, url. | Optional | 
| query | Only entries containing this text (case-insensitive). | Optional | 
| limit | The maximum number of results, 1-1000. Default is 50. | Optional | 
| offset | How many results to skip, for paging. Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EDLManager.Request.ID | String | The request ID. | 
| EDLManager.Request.Entry | String | The IP address, CIDR range, domain, or URL. | 
| EDLManager.Request.Type | String | The entry type: ip, domain, or url. | 
| EDLManager.Request.Status | String | Where the request is now: pending, approved, denied, or deleted \(approved, then removed from the blocklist\). | 
| EDLManager.Request.Priority | String | The priority: low, medium, high, or critical. | 
| EDLManager.Request.Justification | String | Why the entry should be blocked. | 
| EDLManager.Request.Comment | String | An additional comment from the submitter. | 
| EDLManager.Request.ServiceNowTicket | String | The ServiceNow ticket for the request. | 
| EDLManager.Request.SubmittedBy | String | Who submitted the request. Submissions through the API show as api:&lt;key name&gt;. | 
| EDLManager.Request.SubmittedAt | Date | When the request was submitted. | 

#### Command example
```!edl-manager-request-list limit=10```
#### Context Example
```json
{
    "EDLManager": {
        "Request": [
            {
                "ID": "req_6add186a31f47_29b66601",
                "Entry": "https://login.example.net/verify",
                "Type": "url",
                "Status": "pending",
                "Priority": "high",
                "Justification": "Phishing campaign from incident 4821",
                "ServiceNowTicket": "SIR0004821",
                "SubmittedBy": "api:xsoar-prod",
                "SubmittedAt": "2026-10-24T20:43:22+00:00"
            },
            {
                "ID": "req_6add186a31f3e_670eff31",
                "Entry": "phish.example.org",
                "Type": "domain",
                "Status": "pending",
                "Priority": "high",
                "Justification": "Phishing campaign from incident 4821",
                "ServiceNowTicket": "SIR0004821",
                "SubmittedBy": "api:xsoar-prod",
                "SubmittedAt": "2026-10-24T20:43:22+00:00"
            },
            {
                "ID": "req_6add186a31eef_5286cdde",
                "Entry": "203.0.113.10",
                "Type": "ip",
                "Status": "pending",
                "Priority": "high",
                "Justification": "Phishing campaign from incident 4821",
                "ServiceNowTicket": "SIR0004821",
                "SubmittedBy": "api:xsoar-prod",
                "SubmittedAt": "2026-10-24T20:43:22+00:00"
            }
        ]
    }
}
```

#### Human Readable Output

>### Pending EDL Manager requests
>|ID|Entry|Type|Status|Priority|ServiceNowTicket|SubmittedBy|SubmittedAt|
>|---|---|---|---|---|---|---|---|
>| req_6add186a31f47_29b66601 | https://login.example.net/verify | url | pending | high | SIR0004821 | api:xsoar-prod | 2026-10-24T20:43:22+00:00 |
>| req_6add186a31f3e_670eff31 | phish.example.org | domain | pending | high | SIR0004821 | api:xsoar-prod | 2026-10-24T20:43:22+00:00 |
>| req_6add186a31eef_5286cdde | 203.0.113.10 | ip | pending | high | SIR0004821 | api:xsoar-prod | 2026-10-24T20:43:22+00:00 |
>Showing 3 of 3 (offset 0).

### edl-manager-request-approve

***
Approves a pending request and publishes the entry to its blocklist. The API key needs the approve permission.

#### Base Command

`edl-manager-request-approve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The request ID. | Required | 
| comment | A comment recorded with the approval. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EDLManager.Entry.ID | String | The blocklist entry ID. | 
| EDLManager.Entry.Entry | String | The IP address, CIDR range, domain, or URL. | 
| EDLManager.Entry.Type | String | The entry type: ip, domain, or url. | 
| EDLManager.Entry.Status | String | active, or deleted if it was removed from the blocklist. | 
| EDLManager.Entry.Priority | String | The priority: low, medium, high, or critical. | 
| EDLManager.Entry.Justification | String | Why the entry is blocked. | 
| EDLManager.Entry.Comment | String | An additional comment from the submitter. | 
| EDLManager.Entry.ServiceNowTicket | String | The ServiceNow ticket for the request. | 
| EDLManager.Entry.RequestID | String | The ID of the request that added the entry. | 
| EDLManager.Entry.SubmittedBy | String | Who submitted the request. | 
| EDLManager.Entry.SubmittedAt | Date | When the request was submitted. | 
| EDLManager.Entry.ApprovedBy | String | Who approved the request. | 
| EDLManager.Entry.ApprovedAt | Date | When the entry was approved and published. | 
| EDLManager.Entry.ApprovalComment | String | The approver's comment. | 
| EDLManager.Entry.DeletedBy | String | Who removed the entry from the blocklist. | 
| EDLManager.Entry.DeletedAt | Date | When the entry was removed from the blocklist. | 
| EDLManager.Entry.DeletionReason | String | Why the entry was removed. | 

#### Command example
```!edl-manager-request-approve request_id=req_6add186a31eef_5286cdde comment="Confirmed phishing infrastructure"```
#### Context Example
```json
{
    "EDLManager": {
        "Entry": {
            "Entry": "203.0.113.10",
            "Type": "ip",
            "Status": "active",
            "Priority": "high",
            "Justification": "Phishing campaign from incident 4821",
            "ServiceNowTicket": "SIR0004821",
            "SubmittedBy": "api:xsoar-prod",
            "SubmittedAt": "2026-10-24T20:43:22+00:00",
            "ID": "app_6add186a364336.19620368",
            "RequestID": "req_6add186a31eef_5286cdde",
            "ApprovedBy": "api:xsoar-prod",
            "ApprovedAt": "2026-10-24T20:43:22+00:00",
            "ApprovalComment": "Confirmed phishing infrastructure"
        }
    }
}
```

#### Human Readable Output

>### Approved: 203.0.113.10 is on the ip blocklist
>|ID|Entry|Type|Status|Priority|ServiceNowTicket|ApprovedBy|ApprovedAt|
>|---|---|---|---|---|---|---|---|
>| app_6add186a364336.19620368 | 203.0.113.10 | ip | active | high | SIR0004821 | api:xsoar-prod | 2026-10-24T20:43:22+00:00 |

### edl-manager-request-deny

***
Denies a pending request. The API key needs the approve permission.

#### Base Command

`edl-manager-request-deny`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The request ID. | Required | 
| reason | Why the request is denied. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EDLManager.Request.ID | String | The request ID. | 
| EDLManager.Request.Entry | String | The IP address, CIDR range, domain, or URL. | 
| EDLManager.Request.Type | String | The entry type: ip, domain, or url. | 
| EDLManager.Request.Status | String | Where the request is now: pending, approved, denied, or deleted \(approved, then removed from the blocklist\). | 
| EDLManager.Request.Priority | String | The priority: low, medium, high, or critical. | 
| EDLManager.Request.Justification | String | Why the entry should be blocked. | 
| EDLManager.Request.Comment | String | An additional comment from the submitter. | 
| EDLManager.Request.ServiceNowTicket | String | The ServiceNow ticket for the request. | 
| EDLManager.Request.SubmittedBy | String | Who submitted the request. Submissions through the API show as api:&lt;key name&gt;. | 
| EDLManager.Request.SubmittedAt | Date | When the request was submitted. | 
| EDLManager.Request.DeniedBy | String | Who denied the request. | 
| EDLManager.Request.DeniedAt | Date | When the request was denied. | 
| EDLManager.Request.Reason | String | Why the request was denied. | 

#### Command example
```!edl-manager-request-deny request_id=req_6add186a31f3e_670eff31 reason="Shared hosting; blocking would affect other sites"```
#### Context Example
```json
{
    "EDLManager": {
        "Request": {
            "ID": "req_6add186a31f3e_670eff31",
            "Entry": "phish.example.org",
            "Type": "domain",
            "Status": "denied",
            "Priority": "high",
            "Justification": "Phishing campaign from incident 4821",
            "ServiceNowTicket": "SIR0004821",
            "SubmittedBy": "api:xsoar-prod",
            "SubmittedAt": "2026-10-24T20:43:22+00:00",
            "DeniedBy": "api:xsoar-prod",
            "DeniedAt": "2026-10-24T20:43:22+00:00",
            "Reason": "Shared hosting; blocking would affect other sites"
        }
    }
}
```

#### Human Readable Output

>### Denied: phish.example.org
>|ID|Entry|Type|Status|Priority|ServiceNowTicket|SubmittedBy|SubmittedAt|Reason|
>|---|---|---|---|---|---|---|---|---|
>| req_6add186a31f3e_670eff31 | phish.example.org | domain | denied | high | SIR0004821 | api:xsoar-prod | 2026-10-24T20:43:22+00:00 | Shared hosting; blocking would affect other sites |

### edl-manager-entry-list

***
Lists blocklist entries, newest first. The API key needs the view permission.

#### Base Command

`edl-manager-entry-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | active entries, deleted (removed) entries, or all. Possible values are: active, deleted, all. Default is active. | Optional | 
| type | Only entries of this type. Possible values are: ip, domain, url. | Optional | 
| query | Only entries containing this text (case-insensitive). | Optional | 
| limit | The maximum number of results, 1-1000. Default is 50. | Optional | 
| offset | How many results to skip, for paging. Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EDLManager.Entry.ID | String | The blocklist entry ID. | 
| EDLManager.Entry.Entry | String | The IP address, CIDR range, domain, or URL. | 
| EDLManager.Entry.Type | String | The entry type: ip, domain, or url. | 
| EDLManager.Entry.Status | String | active, or deleted if it was removed from the blocklist. | 
| EDLManager.Entry.Priority | String | The priority: low, medium, high, or critical. | 
| EDLManager.Entry.Justification | String | Why the entry is blocked. | 
| EDLManager.Entry.Comment | String | An additional comment from the submitter. | 
| EDLManager.Entry.ServiceNowTicket | String | The ServiceNow ticket for the request. | 
| EDLManager.Entry.RequestID | String | The ID of the request that added the entry. | 
| EDLManager.Entry.SubmittedBy | String | Who submitted the request. | 
| EDLManager.Entry.SubmittedAt | Date | When the request was submitted. | 
| EDLManager.Entry.ApprovedBy | String | Who approved the request. | 
| EDLManager.Entry.ApprovedAt | Date | When the entry was approved and published. | 
| EDLManager.Entry.ApprovalComment | String | The approver's comment. | 
| EDLManager.Entry.DeletedBy | String | Who removed the entry from the blocklist. | 
| EDLManager.Entry.DeletedAt | Date | When the entry was removed from the blocklist. | 
| EDLManager.Entry.DeletionReason | String | Why the entry was removed. | 

#### Command example
```!edl-manager-entry-list type=ip```
#### Context Example
```json
{
    "EDLManager": {
        "Entry": [
            {
                "Entry": "203.0.113.10",
                "Type": "ip",
                "Status": "active",
                "Priority": "high",
                "Justification": "Phishing campaign from incident 4821",
                "ServiceNowTicket": "SIR0004821",
                "SubmittedBy": "api:xsoar-prod",
                "SubmittedAt": "2026-10-24T20:43:22+00:00",
                "ID": "app_6add186a364336.19620368",
                "RequestID": "req_6add186a31eef_5286cdde",
                "ApprovedBy": "api:xsoar-prod",
                "ApprovedAt": "2026-10-24T20:43:22+00:00",
                "ApprovalComment": "Confirmed phishing infrastructure"
            }
        ]
    }
}
```

#### Human Readable Output

>### EDL Manager blocklist entries
>|ID|Entry|Type|Status|Priority|ServiceNowTicket|ApprovedBy|ApprovedAt|
>|---|---|---|---|---|---|---|---|
>| app_6add186a364336.19620368 | 203.0.113.10 | ip | active | high | SIR0004821 | api:xsoar-prod | 2026-10-24T20:43:22+00:00 |
>Showing 1 of 1 (offset 0).

### edl-manager-entry-get

***
Gets a blocklist entry. The API key needs the view permission.

#### Base Command

`edl-manager-entry-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The blocklist entry ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EDLManager.Entry.ID | String | The blocklist entry ID. | 
| EDLManager.Entry.Entry | String | The IP address, CIDR range, domain, or URL. | 
| EDLManager.Entry.Type | String | The entry type: ip, domain, or url. | 
| EDLManager.Entry.Status | String | active, or deleted if it was removed from the blocklist. | 
| EDLManager.Entry.Priority | String | The priority: low, medium, high, or critical. | 
| EDLManager.Entry.Justification | String | Why the entry is blocked. | 
| EDLManager.Entry.Comment | String | An additional comment from the submitter. | 
| EDLManager.Entry.ServiceNowTicket | String | The ServiceNow ticket for the request. | 
| EDLManager.Entry.RequestID | String | The ID of the request that added the entry. | 
| EDLManager.Entry.SubmittedBy | String | Who submitted the request. | 
| EDLManager.Entry.SubmittedAt | Date | When the request was submitted. | 
| EDLManager.Entry.ApprovedBy | String | Who approved the request. | 
| EDLManager.Entry.ApprovedAt | Date | When the entry was approved and published. | 
| EDLManager.Entry.ApprovalComment | String | The approver's comment. | 
| EDLManager.Entry.DeletedBy | String | Who removed the entry from the blocklist. | 
| EDLManager.Entry.DeletedAt | Date | When the entry was removed from the blocklist. | 
| EDLManager.Entry.DeletionReason | String | Why the entry was removed. | 

#### Command example
```!edl-manager-entry-get entry_id=app_6add186a364336.19620368```
#### Context Example
```json
{
    "EDLManager": {
        "Entry": {
            "Entry": "203.0.113.10",
            "Type": "ip",
            "Status": "active",
            "Priority": "high",
            "Justification": "Phishing campaign from incident 4821",
            "ServiceNowTicket": "SIR0004821",
            "SubmittedBy": "api:xsoar-prod",
            "SubmittedAt": "2026-10-24T20:43:22+00:00",
            "ID": "app_6add186a364336.19620368",
            "RequestID": "req_6add186a31eef_5286cdde",
            "ApprovedBy": "api:xsoar-prod",
            "ApprovedAt": "2026-10-24T20:43:22+00:00",
            "ApprovalComment": "Confirmed phishing infrastructure"
        }
    }
}
```

#### Human Readable Output

>### EDL Manager entry 203.0.113.10
>|ID|Entry|Type|Status|Priority|Justification|ServiceNowTicket|SubmittedBy|SubmittedAt|RequestID|ApprovedBy|ApprovedAt|ApprovalComment|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| app_6add186a364336.19620368 | 203.0.113.10 | ip | active | high | Phishing campaign from incident 4821 | SIR0004821 | api:xsoar-prod | 2026-10-24T20:43:22+00:00 | req_6add186a31eef_5286cdde | api:xsoar-prod | 2026-10-24T20:43:22+00:00 | Confirmed phishing infrastructure |

### edl-manager-entry-remove

***
Removes an entry from the blocklist and republishes the list. The record is kept with status deleted. The API key needs the remove permission.

#### Base Command

`edl-manager-entry-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The blocklist entry ID. | Required | 
| reason | Why the entry is removed. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EDLManager.Entry.ID | String | The blocklist entry ID. | 
| EDLManager.Entry.Entry | String | The IP address, CIDR range, domain, or URL. | 
| EDLManager.Entry.Type | String | The entry type: ip, domain, or url. | 
| EDLManager.Entry.Status | String | active, or deleted if it was removed from the blocklist. | 
| EDLManager.Entry.Priority | String | The priority: low, medium, high, or critical. | 
| EDLManager.Entry.Justification | String | Why the entry is blocked. | 
| EDLManager.Entry.Comment | String | An additional comment from the submitter. | 
| EDLManager.Entry.ServiceNowTicket | String | The ServiceNow ticket for the request. | 
| EDLManager.Entry.RequestID | String | The ID of the request that added the entry. | 
| EDLManager.Entry.SubmittedBy | String | Who submitted the request. | 
| EDLManager.Entry.SubmittedAt | Date | When the request was submitted. | 
| EDLManager.Entry.ApprovedBy | String | Who approved the request. | 
| EDLManager.Entry.ApprovedAt | Date | When the entry was approved and published. | 
| EDLManager.Entry.ApprovalComment | String | The approver's comment. | 
| EDLManager.Entry.DeletedBy | String | Who removed the entry from the blocklist. | 
| EDLManager.Entry.DeletedAt | Date | When the entry was removed from the blocklist. | 
| EDLManager.Entry.DeletionReason | String | Why the entry was removed. | 

#### Command example
```!edl-manager-entry-remove entry_id=app_6add186a364336.19620368 reason="Campaign takedown confirmed"```
#### Context Example
```json
{
    "EDLManager": {
        "Entry": {
            "Entry": "203.0.113.10",
            "Type": "ip",
            "Status": "deleted",
            "Priority": "high",
            "Justification": "Phishing campaign from incident 4821",
            "ServiceNowTicket": "SIR0004821",
            "SubmittedBy": "api:xsoar-prod",
            "SubmittedAt": "2026-10-24T20:43:22+00:00",
            "ID": "app_6add186a364336.19620368",
            "RequestID": "req_6add186a31eef_5286cdde",
            "ApprovedBy": "api:xsoar-prod",
            "ApprovedAt": "2026-10-24T20:43:22+00:00",
            "ApprovalComment": "Confirmed phishing infrastructure",
            "DeletedBy": "api:xsoar-prod",
            "DeletedAt": "2026-10-24T20:44:23+00:00",
            "DeletionReason": "Campaign takedown confirmed"
        }
    }
}
```

#### Human Readable Output

>### Removed 203.0.113.10 from the ip blocklist
>|ID|Entry|Type|Status|DeletedBy|DeletedAt|DeletionReason|
>|---|---|---|---|---|---|---|
>| app_6add186a364336.19620368 | 203.0.113.10 | ip | deleted | api:xsoar-prod | 2026-10-24T20:44:23+00:00 | Campaign takedown confirmed |

### edl-manager-metrics-get

***
Gets impact metrics: time from request to approval, time until a firewall pulls the updated list, and which firewall clients are polling. The API key needs the view permission.

#### Base Command

`edl-manager-metrics-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| days | The size of the window, ending now, in days (1-3650). Default is 30. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EDLManager.Metrics.GeneratedAt | Date | When the metrics were computed. | 
| EDLManager.Metrics.Window.Days | Number | The size of the window, in days. | 
| EDLManager.Metrics.Window.From | Date | Start of the window. | 
| EDLManager.Metrics.Window.To | Date | End of the window. | 
| EDLManager.Metrics.Indicators.Active.Total | Number | Entries blocked right now. | 
| EDLManager.Metrics.Indicators.Active.Ip | Number | IP addresses and CIDR ranges blocked right now. | 
| EDLManager.Metrics.Indicators.Active.Domain | Number | Domains blocked right now. | 
| EDLManager.Metrics.Indicators.Active.Url | Number | URLs blocked right now. | 
| EDLManager.Metrics.Indicators.Added | Number | Entries approved in the window. | 
| EDLManager.Metrics.Indicators.Removed | Number | Entries removed from the blocklists in the window. | 
| EDLManager.Metrics.Requests.Submitted | Number | Requests submitted in the window. | 
| EDLManager.Metrics.Requests.Approved | Number | Requests approved in the window. | 
| EDLManager.Metrics.Requests.Denied | Number | Requests denied in the window. | 
| EDLManager.Metrics.Requests.ApprovalRate | Number | Approved divided by approved plus denied, in the window. | 
| EDLManager.Metrics.Requests.Pending | Number | Requests waiting for approval now. | 
| EDLManager.Metrics.Requests.OldestPendingAgeSeconds | Number | How long the oldest pending request has waited, in seconds. | 
| EDLManager.Metrics.TimeToBlock.Count | Number | Approvals measured for time from request to approval. | 
| EDLManager.Metrics.TimeToBlock.MedianSeconds | Number | Median time from request to approval, in seconds. | 
| EDLManager.Metrics.TimeToBlock.P90Seconds | Number | 90th percentile time from request to approval, in seconds. | 
| EDLManager.Metrics.TimeToBlock.ByPriority | Unknown | The same figures for each priority. | 
| EDLManager.Metrics.TimeToEnforcement.Count | Number | Approvals measured for time until a firewall fetched the updated list. | 
| EDLManager.Metrics.TimeToEnforcement.MedianSeconds | Number | Median time from approval until a firewall first fetched the updated list, in seconds. | 
| EDLManager.Metrics.TimeToEnforcement.P90Seconds | Number | 90th percentile time from approval until a firewall first fetched the updated list, in seconds. | 
| EDLManager.Metrics.TimeToEnforcement.Coverage | Number | Share of approvals in the window that could be measured \(fetch tracking was running\). | 
| EDLManager.Metrics.RequestToEnforcement.Count | Number | Requests measured from submission until a firewall fetched the updated list. | 
| EDLManager.Metrics.RequestToEnforcement.MedianSeconds | Number | Median time from request until a firewall first fetched the updated list, in seconds. | 
| EDLManager.Metrics.RequestToEnforcement.P90Seconds | Number | 90th percentile time from request until a firewall first fetched the updated list, in seconds. | 
| EDLManager.Metrics.Firewalls.Tracking | Boolean | Whether any list fetch has been recorded. | 
| EDLManager.Metrics.Firewalls.Total | Number | Firewall clients \(address and user agent pairs\) that have fetched a list. | 
| EDLManager.Metrics.Firewalls.Polling | Number | Firewall clients polling on schedule. | 
| EDLManager.Metrics.Firewalls.Stale | Number | Firewall clients that stopped polling. | 
| EDLManager.Metrics.Firewalls.Clients.Ip | String | The client's source address. | 
| EDLManager.Metrics.Firewalls.Clients.UserAgent | String | The client's user agent. | 
| EDLManager.Metrics.Firewalls.Clients.Lists | String | The lists the client fetches. | 
| EDLManager.Metrics.Firewalls.Clients.FirstSeen | Date | When the client first fetched a list. | 
| EDLManager.Metrics.Firewalls.Clients.LastSeen | Date | When the client last fetched a list. | 
| EDLManager.Metrics.Firewalls.Clients.TypicalIntervalSeconds | Number | How often the client polls, in seconds. | 
| EDLManager.Metrics.Firewalls.Clients.Stale | Boolean | Whether the client stopped polling. | 
| EDLManager.Metrics.Lists | Unknown | For each list \(Ip, Domain, Url\): entries, when it was published and last fetched, and clients in the last 24 hours. | 
| EDLManager.Metrics.Summary | String | Plain-language summary lines for reports. | 

#### Command example
```!edl-manager-metrics-get days=30```
#### Context Example
```json
{
    "EDLManager": {
        "Metrics": {
            "GeneratedAt": "2026-10-24T20:44:23+00:00",
            "Window": {
                "Days": 30,
                "From": "2026-09-24T20:44:23+00:00",
                "To": "2026-10-24T20:44:23+00:00"
            },
            "Indicators": {
                "Active": {
                    "Total": 1,
                    "Ip": 1,
                    "Domain": 0,
                    "Url": 0
                },
                "Added": 1,
                "Removed": 0
            },
            "Requests": {
                "Submitted": 3,
                "Approved": 1,
                "Denied": 1,
                "ApprovalRate": 0.5,
                "Pending": 1,
                "OldestPendingAgeSeconds": 61
            },
            "TimeToBlock": {
                "Count": 1,
                "MedianSeconds": 0,
                "P90Seconds": 0,
                "ByPriority": {
                    "Critical": {
                        "Count": 0,
                        "MedianSeconds": null,
                        "P90Seconds": null
                    },
                    "High": {
                        "Count": 1,
                        "MedianSeconds": 0,
                        "P90Seconds": 0
                    },
                    "Medium": {
                        "Count": 0,
                        "MedianSeconds": null,
                        "P90Seconds": null
                    },
                    "Low": {
                        "Count": 0,
                        "MedianSeconds": null,
                        "P90Seconds": null
                    }
                }
            },
            "TimeToEnforcement": {
                "Count": 1,
                "MedianSeconds": 61,
                "P90Seconds": 61,
                "Coverage": 1
            },
            "RequestToEnforcement": {
                "Count": 1,
                "MedianSeconds": 61,
                "P90Seconds": 61
            },
            "Firewalls": {
                "Tracking": true,
                "Total": 2,
                "Polling": 2,
                "Stale": 0,
                "Clients": [
                    {
                        "Ip": "172.17.0.1",
                        "UserAgent": "PAN-OS/11.1 (fw-dc1-01)",
                        "Lists": [
                            "ip"
                        ],
                        "FirstSeen": "2026-10-24T20:43:20+00:00",
                        "LastSeen": "2026-10-24T20:44:23+00:00",
                        "TypicalIntervalSeconds": 63,
                        "Stale": false
                    },
                    {
                        "Ip": "172.17.0.1",
                        "UserAgent": "FortiGate-60F v7.4",
                        "Lists": [
                            "ip"
                        ],
                        "FirstSeen": "2026-10-24T20:44:23+00:00",
                        "LastSeen": "2026-10-24T20:44:23+00:00",
                        "TypicalIntervalSeconds": null,
                        "Stale": false
                    }
                ]
            },
            "Lists": {
                "Ip": {
                    "Entries": 1,
                    "PublishedAt": "2026-10-24T20:43:22+00:00",
                    "LastFetchAt": "2026-10-24T20:44:23+00:00",
                    "ClientsLast24H": 2,
                    "CurrentVersionFetched": true
                },
                "Domain": {
                    "Entries": 0,
                    "PublishedAt": "2026-10-24T20:43:22+00:00",
                    "LastFetchAt": null,
                    "ClientsLast24H": 0,
                    "CurrentVersionFetched": false
                },
                "Url": {
                    "Entries": 0,
                    "PublishedAt": "2026-10-24T20:43:22+00:00",
                    "LastFetchAt": null,
                    "ClientsLast24H": 0,
                    "CurrentVersionFetched": false
                }
            },
            "Summary": [
                "Blocked right now: 1 indicator (1 IP address, 0 domains, 0 URLs).",
                "Last 30 days: 1 request approved, 1 denied.",
                "Request to approval: median 0 s, 90% within 0 s.",
                "Approval to the first firewall pulling the updated list: median 1 min, 90% within 1 min.",
                "Request to enforcement on a firewall: median 1 min.",
                "Firewall clients polling the lists: 2."
            ]
        }
    }
}
```

#### Human Readable Output

>### EDL Manager impact, last 30 days
>- Blocked right now: 1 indicator (1 IP address, 0 domains, 0 URLs).
>- Last 30 days: 1 request approved, 1 denied.
>- Request to approval: median 0 s, 90% within 0 s.
>- Approval to the first firewall pulling the updated list: median 1 min, 90% within 1 min.
>- Request to enforcement on a firewall: median 1 min.
>- Firewall clients polling the lists: 2.
>
>### Key numbers
>|Blocked Now|Approved|Denied|Pending|Median Request To Approval (s)|Median Approval To Firewall (s)|Firewall Clients Polling|Firewall Clients Stopped|
>|---|---|---|---|---|---|---|---|
>| 1 | 1 | 1 | 1 | 0 | 61 | 2 | 0 |

