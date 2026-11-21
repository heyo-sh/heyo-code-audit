---
"@heyo-sh/heyo-code-audit": minor
---

Find more real defects and report them like a reviewer:

- Audit the pull request's merge-base diff instead of the moving target branch, so reverted target-branch commits no longer leak into audits and inline comments no longer fail with "Path could not be resolved".
- Split large change sets into parallel discovery passes instead of truncating one prompt, and run verification sessions in parallel.
- Rewrite the audit policy to trace callers and consumers of every changed contract and to keep realistic race, partial-failure, deploy-ordering, performance, and broken-test findings instead of dismissing them as theoretical. Severity now maps to P0–P3 priorities.
- Keep one updatable pull-request summary comment with a 1–5 confidence score, impact, verdict, linked findings, a change summary with an optional diagram, and findings resolved since the last review (`summary-comment`, default `true`).
- Add a fix recommendation to every finding, numbered file reads, base-version reads, per-file diffs, and git-backed repository search.
- Retry a recoverable Pi session once, publish partial coverage instead of failing the whole audit, and fall back to Check and summary reporting when GitHub rejects an inline comment location.
