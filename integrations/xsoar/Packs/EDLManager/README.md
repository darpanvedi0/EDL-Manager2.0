[EDL Manager](https://github.com/darpanvedi0/EDL-Manager2.0) is an open-source approval workflow for firewall blocklists. Analysts and tools submit IP addresses, CIDR ranges, domains, and URLs; an approver reviews each request; approved entries are published as External Dynamic Lists (EDLs) that firewalls fetch, such as Palo Alto Networks PAN-OS, Fortinet FortiGate, and Check Point.

## What does this pack do?

- Submit indicators from an incident for blocking, with the justification and ServiceNow ticket the approver needs.
- Poll a request until it is approved or denied, then continue the playbook.
- Approve or deny pending requests, or remove entries from the blocklist, from a playbook or the War Room.
- List what is blocked and what is waiting for approval.
- Get impact metrics: how long approvals take, how long until firewalls pull the updated list, and which firewalls have stopped polling.

Entries submitted from Cortex XSOAR go through the same approval step and audit log as entries submitted in the EDL Manager web interface. They show as submitted by `api:<key name>`.

This pack requires EDL Manager 2.1 or later, which provides the REST API.
