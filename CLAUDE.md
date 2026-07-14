# CLAUDE.md — editing `stack.yml`

`stack.yml` is the watch-list StackWatch queries against osv.dev. This file is
curated by hand; the rules below decide what goes in it and why. When adding or
removing entries, follow these — don't just dump a dependency list.

## The one question

Every entry must answer: **"could a CVE here actually compromise us?"** If a
vuln in the package has no path to hurt production, it does not belong here —
even if it's a direct dependency. Coverage is not the goal; *actionable* alert
signal is. Dependabot + bundler-audit already cover direct-dep hygiene in CI;
this file is for the security-relevant subset worth paging a human about.

### What counts as real attack surface (include)
- **Untrusted-input parsers** — XML/HTML (nokogiri, rexml, xmlrpc, loofah,
  sanitize), spreadsheets/PDF on upload/import paths (roo, spreadsheet,
  pdf-reader, kt-paperclip, rubyzip, mimemagic), image/doc binaries invoked on
  user uploads (imagemagick, ghostscript, poppler, libvips).
- **Auth / crypto / SSO / authz** — rails, rack, devise(+2fa/token), doorkeeper,
  jwt, json-jwt, ruby-saml, omniauth(+oauth2), oauth2, cancancan, bcrypt.
- **Network egress / SSRF / untrusted responses** — faraday, httparty,
  rest-client, savon, mail, net-imap, axios.
- **Rich-text / templating with user content** — tinymce, html-react-parser, dompurify.
- **Admin / broad authenticated surface** — rails_admin.
- **Runtime & escape surface** — the Swarm host, container runtime, ingress
  (docker.io, containerd, runc, moby, traefik), OS packages (openssl, openssh,
  sudo, systemd, kernel).
- **EOL / unmaintained** with no clean upstream (wkhtmltopdf-binary) — track manually too.
- **Newly-exposed interfaces** — MCP servers (fast-mcp, mcp).

### What is noise (exclude — a CVE here won't compromise us)
- **Trusted-path clients** — DB/datastore client gems (pg, redis-rb, the
  elasticsearch gem, searchkick): the datastore is trusted input, and the real
  CVEs are already caught by the OS-level Debian entries. Cloud SDKs talking to
  trusted endpoints over TLS (aws-sdk-s3/sqs — keep only aws-sdk-core because
  SQS is the job broker).
- **Output-only libs** — serialize/generate *our* data outward: prawn (PDF
  generation), active_model_serializers, audit writers (paper_trail).
- **Inert controls / wrappers** — recaptcha, geoip (reads a DB we ship).
- **Redundant** — a subset of something already listed (lodash.debounce vs
  lodash; react-dom vs react).
- **Pure client state / UI-logic** — @reduxjs/toolkit, react-hook-form.
- **Dev/test/build/asset tooling** — rubocop, rspec, capybara, nx, vite, swc,
  babel, eslint, bootstrap, jquery, tailwind. Dependabot's job.

Note: pinned entries that turn out low-value are *inert* (they stay silent), but
**unpinned npm** low-value entries actively generate un-actionable alerts — be
strictest about noise there.

## Conventions

- **Pin `version:` whenever a lockfile gives one.** This is the single biggest
  noise reducer: osv.dev filters server-side to vulns affecting that exact
  version, so an up-to-date pin goes near-silent until a *new* affecting CVE
  lands. Leave unpinned only when the version genuinely varies across
  deploys/repos (frontend npm across MFEs; OS packages whose host version is
  unknown — Debian ecosystem is the closest proxy).
- **`tier:` is an informational label only.** It does NOT drive alerting.
  Routing is severity-based (see `filters` in stack.yml): `drop_below_cvss` /
  `digest_below_cvss`, and `@here` only when CVSS ≥ digest threshold AND a patch
  exists. Don't reach for `tier` to make something louder.
- **Keep entries grouped by surface category** with a one-line comment on
  *why* a non-obvious entry is watched (the compromise path), not what it is.
- **When multiple app majors run** (el-ciclo Rails 8 vs zenats/cavall2 Rails
  7.1), pin the same gem twice at each major so a version-specific CVE isn't
  missed by the other pin.
- Verify a change parses: `STACKWATCH_SLACK_WEBHOOK=x ruby -Ilib -e 'require "stackwatch"; StackWatch::Config.load(path:"stack.yml")'`.

## Deployment context (informs scoping)

- Orchestration is **Docker Swarm, not Kubernetes** — skip k8s-only advisories
  (e.g. `runAsNonRoot` bypasses don't apply). `docker.sock` is mounted into
  traefik/portainer/auto-deploy, so container-runtime CVEs are host-root-equivalent.
- Prod is **Ruby/Rails + React**; there is no Python/JVM app, no Laravel, no
  Rust service in prod (don't add PyPI/Maven/crates.io app deps).
- Watched repos: **el-ciclo** (ZenHR/zenhr, Rails 8), **zenats**/**cavall2**
  (Rails 7.1), **mfe-monorepo** (Nx React) + **zenats-react** (frontends).
- Queues are **AWS SQS** (not RabbitMQ); object store is **MinIO**; ingress is
  **Traefik** (not standalone nginx).

## Out of scope for this file (but flag if seen)
Secrets committed to source (e.g. tokens in a Gemfile's git-source URLs) are a
real compromise vector StackWatch can't watch — surface them separately and
recommend rotation + history purge, don't try to encode them here.
