# Test fixtures

`sample-session.mjs` — a tiny normalized Hopper session, used as a deterministic
fixture by every T1/T2 test. Keep it small; this is loaded into a fresh store
in nearly every test.

`index.mjs` — `startServer()` spawns the MCP server in an isolated store path
and gives back a JSON-RPC client. `startWithSample()` adds an `open_session`
of the sample for convenience. Always `await harness.close()` in your `finally`
to avoid leaking servers and tmpdirs.

When tests need real binaries (T2/T3), they fetch from `/usr/bin/*` at start.
We require macOS already, so this is no new constraint and avoids vendoring
binaries.
