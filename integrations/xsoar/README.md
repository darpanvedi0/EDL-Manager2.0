# Cortex XSOAR integration

`Packs/EDLManager` is a Cortex XSOAR content pack for EDL Manager's REST API. It is laid out exactly as in Palo Alto Networks' [demisto/content](https://github.com/demisto/content) repository, so it can be contributed to the XSOAR Marketplace as-is. It passes `demisto-sdk validate`, the content repository's ruff and mypy settings, and its pytest rules.

| Command | API key permission | What it does |
|---------|--------------------|--------------|
| `edl-manager-request-submit` | `submit` | Submit IPs, CIDR ranges, domains, or URLs for approval; skipped entries come back with the reason |
| `edl-manager-request-get` | `view` | Where a request is now: pending, approved, denied, or deleted (use it to poll for the decision) |
| `edl-manager-request-list` | `view` | Pending requests |
| `edl-manager-request-approve` | `approve` | Approve and publish to the blocklist |
| `edl-manager-request-deny` | `approve` | Deny with a reason |
| `edl-manager-entry-list` | `view` | Blocklist entries |
| `edl-manager-entry-get` | `view` | One entry |
| `edl-manager-entry-remove` | `remove` | Remove an entry from the blocklist |
| `edl-manager-metrics-get` | `view` | Impact metrics: time to approval, time until firewalls pull the update, firewalls polling |

The full reference, with examples recorded from a live server, is in [`Packs/EDLManager/Integrations/EDLManager/README.md`](Packs/EDLManager/Integrations/EDLManager/README.md).

## Testing

Both scripts need Docker and a checkout of `demisto/content`, for `CommonServerPython` and the test tooling. A sparse clone is enough:

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/demisto/content ../content
git -C ../content sparse-checkout set Packs/Base/Scripts/CommonServerPython \
    Packs/ApiModules/Scripts/DemistoClassApiModule Tests/demistomock Tests/scripts/dev_envs/pytest

integrations/xsoar/run-tests.sh ../content                        # 29 unit tests, recorded API responses
docker build -t edl-manager:dev . && \
    integrations/xsoar/e2e.sh edl-manager:dev ../content          # every command against a live EDL Manager
```

Both run in the Docker image XSOAR runs the integration in (`dockerimage` in `EDLManager.yml`). CI runs them on every pull request.

## Contributing the pack to the XSOAR Marketplace

Palo Alto Networks' [Content Contribution Guide](https://xsoar.pan.dev/docs/contributing/contributing) is the authoritative process; check it before submitting, as it changes. In outline:

1. **Release EDL Manager first.** The pack requires the REST API, so merge it to `main`, set `APP_VERSION` to `2.1.0` in `config/config.php`, and tag `v2.1.0` so the Docker image is published. Reviewers need a release they can install.
2. **Fork `demisto/content`**, create a branch, and copy `integrations/xsoar/Packs/EDLManager` to `Packs/EDLManager`.
3. **Check it in the fork** with `demisto-sdk validate -i Packs/EDLManager` and `demisto-sdk pre-commit -i Packs/EDLManager`.
4. **Open a pull request** against `master` and fill in the template. A bot asks you to sign the Palo Alto Networks contributor license agreement.
5. **Answer review comments.** Reviewers may ask for a demo or a test instance. `docker compose up` in this repository gives them one, and the API key needs `view`, `submit`, `approve`, and `remove`.

Once merged, the pack ships to the Marketplace with a content release. Keep the pull request link, the merge date, and the Marketplace listing: they show that Palo Alto Networks reviewed and accepted the integration.
