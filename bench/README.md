# Benchmarks

Reproducible performance and accuracy measurements for EDL Manager. `run.sh` runs all three and writes JSON to `results/`; the committed results are the ones the technical write-up reports.

```bash
bench/run.sh                      # builds edl-manager:bench, about 15 minutes
bench/run.sh edl-manager:dev      # or use an image you already built
```

It needs Docker, PHP 8 and Python 3 (standard library only). The HTTP benchmarks run the image hardened as `compose.yaml` runs it, on ports 18101 and 18102 of `127.0.0.1`.

| Script | Measures | Output |
|--------|----------|--------|
| `publish.php` | Time to publish the lists, submit an entry, and approve one, at 1,000 to 100,000 listed entries (median of 7 runs, application code called directly) | `results/publish.json` |
| `http_bench.py` | List downloads per second and latency: Apache serving a static copy, `feed.php` with stable clients, and `feed.php` with a new client every request (a tracking write each time); then REST API latency | `results/http.json` |
| `enforcement.py` | Whether the reported time to enforcement is right: simulated firewalls poll the IP list while entries are approved through the API, and their own first sighting of each entry is compared with `GET /api/v1/metrics` | `results/enforcement.json` |

`results/environment.json` records the CPU, memory, and software versions of the run. The load generator runs on the same host as the server, so throughput figures are lower bounds.

Entries are synthetic (`entries.php`): 60% IPv4 addresses in `10.0.0.0/8`, 30% domains under `example*.com`, 10% URLs under `example.net`. The API benchmarks submit addresses from `198.18.0.0/15`, which RFC 2544 reserves for benchmarking.

`seed.php` runs inside the container: `run.sh` pipes it in to load the entries and create an API key, since `docker cp` can't write to a read-only container.
