# StackWatch

Self-hosted CVE monitoring for your stack. Watches a list of packages and pings your Slack channel the moment a new CVE drops for any of them.

Dependabot covers your repo dependencies. StackWatch covers everything else — your editor, your OS packages, your database, your identity provider, your terminal tools.

---

## Quick start

### GitHub Actions (recommended)

**1. Create `stack.yml` in your repo:**

```yaml
notifications:
  slack:
    webhook_url: "${STACKWATCH_SLACK_WEBHOOK}"

packages:
  - name: rails
    ecosystem: RubyGems
    tier: critical
  - name: django
    ecosystem: PyPI
    tier: standard
```

**2. Add the workflow** (copy [`examples/github-actions.yml`](examples/github-actions.yml) to `.github/workflows/cve-monitor.yml`).

**3. Add your Slack webhook as a repo secret** named `STACKWATCH_SLACK_WEBHOOK`.

That's it. New CVEs appear in your Slack channel within hours of disclosure.

---

### Docker + cron

```bash
# Create your stack config
docker run --rm ghcr.io/yourorg/stackwatch:latest init > stack.yml
# Edit stack.yml

# Run manually
docker run --rm \
  -v $PWD/data:/data \
  -v $PWD/stack.yml:/app/stack.yml:ro \
  -e STACKWATCH_SLACK_WEBHOOK=https://hooks.slack.com/... \
  ghcr.io/yourorg/stackwatch:latest run

# Set up cron (see examples/crontab)
```

---

### Any CI (Bitbucket, GitLab, CircleCI, ...)

```yaml
# Bitbucket Pipelines example
- step:
    name: CVE Monitor
    script:
      - docker run --rm
          -v $BITBUCKET_CLONE_DIR:/work
          -e STACKWATCH_SLACK_WEBHOOK=$STACKWATCH_SLACK_WEBHOOK
          ghcr.io/yourorg/stackwatch:latest run --config /work/stack.yml --state-path /work/state.json
```

---

### Local dev

```bash
git clone https://github.com/yourorg/stackwatch.git
cd stackwatch
bundle install
bin/stackwatch init      # generate stack.yml
bin/stackwatch run       # run once
```

---

## `stack.yml` reference

```yaml
state_path: ./state.json        # where to store seen CVE IDs

notifications:
  slack:
    webhook_url: "${STACKWATCH_SLACK_WEBHOOK}"   # or set env var directly

filters:
  max_age_days: 30              # ignore CVEs older than 30 days (default).
                                # Set `false` to disable the age filter.
  drop_below_cvss: 4.0          # CVSS below this is dropped (default 4.0)
  digest_below_cvss: 7.0        # 4.0..<7.0 -> weekly digest, no @here (default 7.0)

packages:
  - name: rails
    ecosystem: RubyGems
    version: 8.0.5    # optional: osv filters server-side to vulns affecting this version
    tier: critical    # informational label (see below)
  - name: next
    ecosystem: npm
    tier: standard
```

**Routing (severity-based, not tier-based):** alerts are routed by the CVE's CVSS
base score, which StackWatch computes from the enriched osv record:
- `CVSS < drop_below_cvss` — dropped.
- `drop_below_cvss <= CVSS < digest_below_cvss` — batched into a single **digest** message, no mention.
- `CVSS >= digest_below_cvss` — individual channel post; **`@here` only when a patch is available** (high severity you can't act on is a silent post, not a page).
- Unknown severity — digested, never `@here`.

`tier` is now an informational label only; it no longer controls `@here`.

**Filters:**
- `max_age_days` — drop vulnerabilities published more than N days ago. Defaults to `30`. Set to `false` to report every historical CVE (noisy). Withdrawn vulnerabilities are always skipped.
- **Retroactive CVE backfills** are auto-digested (never paged): when a CVE id's year is 2+ years older than its publication date — e.g. `CVE-2022-48xxx` first published in 2026, as the Linux kernel project has been doing en masse — the fix is old news, not a new issue. These route to the quiet digest and, once seen, don't recur.
- `drop_below_cvss` / `digest_below_cvss` — the CVSS routing thresholds above (0–10).
- `version` (per package) — when set, osv.dev filters server-side to vulns that actually affect that version. The biggest noise reducer; up-to-date pins go silent.

**Supported ecosystems:** any ecosystem supported by [osv.dev](https://osv.dev) — PyPI, npm, RubyGems, Go, Maven, Debian, Alpine, NuGet, Hex, crates.io, and more.

---

## Alert format

```
@here :rotating_light: CVE for rails (RubyGems) — CVSS 9.8
CVE-2024-27351 (GHSA-qrr7-9963-x827)
Potential SQL injection in the query builder
Affected: >=3.2.0   Patched in 3.2.25 — upgrade
View on osv.dev
```

`@here` appears only for CVSS ≥ `digest_below_cvss` **with** a patch available.
The advisory is labelled by its real id prefix (CVE / GHSA / PYSEC), and any aliases
are shown in parentheses. Lower-severity findings are grouped into a single digest
message instead.

---

## CLI reference

```
bin/stackwatch run [--config stack.yml] [--state-path state.json]
bin/stackwatch init [--force]
```

**Environment variables:**

| Variable | Description |
|---|---|
| `STACKWATCH_SLACK_WEBHOOK` | Slack Incoming Webhook URL |
| `STACKWATCH_STATE_PATH` | Override path to state.json |

---

## State storage

StackWatch persists seen CVE IDs to `state.json` so it only alerts on new findings. The file path is configurable.

**GitHub Actions:** use `actions/cache` (see [`examples/github-actions.yml`](examples/github-actions.yml)).  
**Cron/VPS:** a local file. Done.  
**Bitbucket/GitLab:** commit back via bot user, or upload as pipeline artifact.

---

## Architecture

```
stack.yml → Config → OSV querybatch (id stubs) → diff vs state
          → enrich unseen ids (/v1/vulns/{id}) → severity route → Slack → state.json
```

- **No database.** State is a JSON file.
- **Two-phase osv fetch:** one cheap `/v1/querybatch` call returns id stubs; only *unseen* ids are enriched via `/v1/vulns/{id}` (that's where CVSS / affected / patch actually live — querybatch omits them). Version pins are applied in the batch query so osv filters server-side.
- **Pluggable notifiers** — v1 ships Slack. Discord/webhook coming in v1.1.
- **Pluggable sources** — v1 ships osv.dev. RSS feeds and GitHub Advisory DB coming in v1.1.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and PRs welcome.

---

## License

MIT — see [LICENSE](LICENSE).
