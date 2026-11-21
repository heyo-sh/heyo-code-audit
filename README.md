<div align="center">
  <h1>Heyo Code Audit</h1>
  <p>Verified AI code reviews for GitHub pull requests.</p>

  <p>
    <a href="https://github.com/marketplace/actions/heyo-code-audit"><img src="https://img.shields.io/badge/GitHub%20Marketplace-Heyo%20Code%20Audit-000000?style=flat&amp;logo=github&amp;logoColor=white" alt="GitHub Marketplace"/></a>
    <a href="https://github.com/heyo-sh/heyo-code-audit/releases"><img src="https://img.shields.io/github/v/release/heyo-sh/heyo-code-audit?display_name=tag&amp;sort=semver&amp;style=flat&amp;colorA=000000&amp;colorB=000000" alt="GitHub release"/></a>
    <a href="https://github.com/heyo-sh/heyo-code-audit/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/heyo-sh/heyo-code-audit/ci.yml?branch=main&amp;style=flat&amp;label=checks&amp;colorA=000000&amp;colorB=000000" alt="checks"/></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-000000?style=flat&amp;colorA=000000&amp;colorB=000000" alt="MIT License"/></a>
  </p>

  <p style="margin-top: 0.375rem;">
    <a href="https://heyo.sh/heyo-code-audit/introduction">Documentation</a>
    ·
    <a href="https://github.com/marketplace/actions/heyo-code-audit">Marketplace</a>
    ·
    <a href="https://github.com/heyo-sh/heyo-code-audit/discussions">Discussions</a>
  </p>
</div>

## Heyo Code Audit

Heyo Code Audit reviews GitHub pull requests with an AI model from Pi's bundled
provider catalog. It audits exactly the change GitHub shows — the diff from the
pull request's merge base — traces every changed signature, schema, and field to
its callers and consumers in the repository, then verifies every candidate
finding in a separate Pi session before publishing results as a GitHub Check,
inline review comments, and one pull-request summary comment.

It looks for security, regression, functional, and non-functional defects,
including the ones reviewers most often miss: lost updates and races, partial
failures, rolling-deploy and migration compatibility, stale UI state, error
misclassification, performance traps on realistic data, and tests that cannot
fail. Large pull requests are split into parallel discovery passes so no file
falls out of a truncated prompt; lockfiles, generated files, and binaries are
listed but not audited.

Each finding carries a priority (P0 critical, P1 high, P2 medium, P3 low), the
trigger and impact, a concrete fix, and — when one line fully fixes it — an
apply-able suggestion. Applicable root and nested `AGENTS.md` files from the PR
target's base commit supply repository-specific requirements for changed paths,
with the nearest file taking precedence. Guidance is bounded and treated as
untrusted for auditor operations; changes to `AGENTS.md` in the PR cannot
rewrite the rules used to review that PR. If applicable guidance exceeds the
limit, the audit fails rather than silently ignoring it. Audits reject
speculative findings and plausible product decisions, but not realistic timing,
concurrency, or deploy-ordering defects.

### The summary comment

Heyo keeps one comment on the pull request up to date after every audit:

- **Confidence Score: N/5** — 5 with no verified findings, 4 with only
  non-blocking findings, 3 with one high finding, 2 with several high findings
  or one critical, and 1 with several critical findings. Partial coverage caps
  the score at 4.
- The impact of the change and a one-line verdict, such as “Fix 1 blocking
  finding before merging.”
- Every finding with its priority and a link to its inline comment; findings
  outside the diff are listed in full.
- A summary of what the change does, with a flow diagram when it implements a
  multi-step flow.
- Findings resolved since the previous review, the review count, the last
  reviewed commit, and how many changed files were covered.

Set `summary-comment: false` to turn it off.

## Get started

Add this workflow to `.github/workflows/heyo-code-audit.yml`, then add the
provider credential as a GitHub Actions secret.

```yaml
name: Heyo Code Audit

on:
  pull_request:
    types: [opened, synchronize, reopened]

concurrency:
  group: heyo-code-audit-${{ github.event.pull_request.number }}
  cancel-in-progress: true

permissions:
  contents: read
  pull-requests: write
  checks: write

jobs:
  audit:
    runs-on: ubuntu-latest
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: heyo-sh/heyo-code-audit@v1
        with:
          provider: openai
          model: gpt-5.4
          auth-type: api-key
          auth-token: ${{ secrets.OPENAI_API_KEY }}
          github-token: ${{ github.token }}
```

Use the stable `@v1` reference for the latest compatible release, or pin an
immutable tag such as `@v1.1.1`.

## Minimum configuration

The Action requires an explicit `provider`, `model`, authentication mode, and
provider credential. API-key providers use `auth-type: api-key`; GitHub Copilot
and OpenAI Codex use `oauth`; Amazon Bedrock supports `aws` or
`bedrock-bearer`.

The default report mode creates both a **Heyo Code Audit** GitHub Check and an
inline pull-request review. While the audit runs, Heyo adds an 👀 reaction to
the pull request. It replaces it with 👍 only when there are no verified
findings; otherwise it removes the 👀 reaction when the review finishes.
Configure reporting, severity thresholds, paths, incremental runs, and commit
limits in the Action inputs. Commit-limit skips remain neutral. An unexpected
audit error returns `errored`, fails the Action job and, when reporting is still
available, publishes a failed Check without advancing incremental state.
The Action log distinguishes Pi turn-limit and deadline failures from provider
or runtime errors. Discovery passes allow up to 120 Pi turns and 20 minutes,
verification sessions 60 turns and 12 minutes, and the summary 12 turns; the
limits are safety ceilings, not targets. Up to four sessions run in parallel. A
session that fails early on a provider error or a malformed answer is retried
once; an exhausted turn budget or deadline, or a late failure, is not. When some sessions still fail, the
report is published with partial coverage and the incremental state is not
advanced; when every discovery pass or every verification fails, the audit
errors. Inline comments GitHub rejects never fail an audit — those findings stay
in the Check and the summary comment. Pi session errors are categorized by HTTP
status or transport failure when possible, without logging the raw Pi error
text.

Check out the repository with `fetch-depth: 0`: Heyo needs the merge base of the
pull request.

## Langfuse tracing

Set `langfuse-public-key` and `langfuse-secret-key` to trace every Pi session in
[Langfuse](https://langfuse.com): the session as an agent observation, each
model call as a generation with tokens and cost, and each tool call. Sessions
of one pull-request head share a Langfuse session, and traces carry the
repository, pull-request number and audit phase.

```yaml
- uses: heyo-sh/heyo-code-audit@v1
  with:
    # ...the inputs above
    langfuse-public-key: ${{ secrets.LANGFUSE_PUBLIC_KEY }}
    langfuse-secret-key: ${{ secrets.LANGFUSE_SECRET_KEY }}
    langfuse-base-url: https://cloud.langfuse.com
    langfuse-environment: ci
```

Traces contain the audit prompt with the bounded diff, model output, and the
repository content that tools return, each text cut at 20,000 characters.
Configured secrets and common credential formats are redacted before export,
and provider errors are recorded only as their category. Tracing never changes
audit results or incremental state, and a Langfuse failure never fails the
audit. Fork pull requests without access to the secrets are not traced.

## Documentation

Read the [Heyo Code Audit documentation](https://heyo.sh/heyo-code-audit/introduction)
for the [quickstart](https://heyo.sh/heyo-code-audit/quickstart), provider
setup, Action inputs, reporting behaviour, safety boundaries, and
troubleshooting. See the [provider guide](https://heyo.sh/heyo-code-audit/providers)
for copyable configurations and [Pi's provider documentation](https://github.com/earendil-works/pi/blob/main/docs/providers.md)
for provider and model details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local development and contribution
guidelines. Use [GitHub Discussions](https://github.com/heyo-sh/heyo-code-audit/discussions)
for questions and [SECURITY.md](SECURITY.md) to report vulnerabilities privately.

## License

[MIT](LICENSE)
