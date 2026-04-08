# Contributing

This project should stay boring in the places that matter: clear commits,
small changes, explicit safety gates, and tests that exercise real MCP calls.

## Commit Messages

Use the Go project commit message style:

```text
area: lowercase action phrase
```

Examples:

```text
mcp: add protocol negotiation test
hopper: fix live exporter timeout handling
macho: preserve function discovery caps
docs: document client setup
```

Rules:

- Put the affected area before the colon, such as `mcp`, `hopper`, `macho`,
  `docs`, `test`, or `repo`.
- Use a lowercase verb after the colon.
- Write the subject so it completes: "this change modifies the project to ...".
- Keep the subject short, ideally under 72 characters.
- Do not add a trailing period to the subject.
- If a body is needed, wrap it around 72 columns.
- Do not use Markdown in commit message bodies.
- Do not add `Signed-off-by` lines.

Reference: https://go.dev/wiki/CommitMessage

## Code Quality

- Prefer small, reviewable changes over broad rewrites.
- Keep JavaScript production-grade: clear module boundaries, explicit errors,
  bounded output, and tests for new MCP behavior.
- Keep generated Python exporter code deterministic and easy to inspect.
- Avoid private Hopper APIs, code injection, SIP-disabling flows, or copied
  proprietary implementation details.
- Use Hopper's official MCP server only as a subprocess interface or behavior
  reference.
- Keep live writes guarded. Hopper write-back must require an explicit preview,
  an opt-in environment variable, and a per-call confirmation.

## Tests

Run the fast checks before pushing:

```bash
npm run check
npm run test:protocol
npm run smoke
npm run test:real
npm run test:official
```

Run the live audit before changing Hopper integration:

```bash
LIVE_HOPPER_PARSE_OBJC=0 LIVE_HOPPER_PARSE_SWIFT=0 LIVE_HOPPER_ANALYSIS=0 LIVE_HOPPER_TIMEOUT_MS=90000 LIVE_HOPPER_MAX_FUNCTIONS=20 LIVE_HOPPER_MAX_STRINGS=50 npm run test:tools
```

If a live Hopper test cannot run because macOS Automation is blocked, say that
explicitly in the PR or change notes.
