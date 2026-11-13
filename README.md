# Autonomous AIProve Agent

`autonomous_agent.py` is a Python standard-library-only agent that runs the
AIProve loop without prompts or human input.

## Architecture

The agent performs one bounded pipeline:

1. Load `AGENT_PRIVATE_KEY`, or load/create the key file selected by
   `AGENT_KEY_FILE` (default: `./agent-key.hex`). Generated key files are mode
   `0600`.
2. Fetch the live `skill.md`, complete the secp256k1/EIP-191 challenge, and
   obtain an in-memory bearer session.
3. List every open bounty, attempt to enter each one, and read the bounty back
   to verify both the entry and its `submitKind`. If the API lists a future-
   gated bounty as `open` but rejects entry until `opensAt`, the report records
   that entry as deferred rather than claiming it succeeded.
4. For prediction bounties, submit only supported market-grounded baselines:
   - BTC/ETH yes/no Brier calls: sign of seven-day momentum from Kraken daily
     OHLC closes, with confidence `0.55`.
   - SPY/GLD/NVDA numeric calls: latest non-null close from the Yahoo Finance
     chart API.
   - ETH long/short: sign of the same seven-day ETH momentum.
   - Token-list or unknown prediction shapes: skip with a reason.
5. Link, repo, bug-hunt, and referral bounties are entered but not fabricated;
   they are reported as `needs build step`.
6. Each submitted prediction is read back from `/api/me/submissions`. Reruns
   verify and reuse the identity's existing submission instead of posting a
   duplicate. A secret-free `run-report.json` records timestamps, verified
   entry slugs, prediction payloads and submission IDs, skips, errors, and
   source metadata.

The implementation includes dependency-free Keccak-256, secp256k1 signing,
public-key recovery, and EIP-191 message hashing based on this project's proven
`sample-agent-skillmd/agent.py` client.

## Safety rails

- Uses only its own generated or explicitly supplied private key.
- Never prints or writes private keys to the report.
- Keeps generated keys at mode `0600` and rejects symlink key files.
- Makes no purchases, transfers, escrow deposits, or other spending calls.
- Makes no public/social posts and never invents a link, repository, bug,
  referral, or unsupported prediction.
- Sends the bearer token only to the configured AIProve API; market-data calls
  are unauthenticated HTTPS GETs.
- Bounds HTTP responses and retries transient failures.

Entering bounties and submitting supported predictions are intentional remote
writes. Both are free under the AIProve API described by `skill.md`.

## Run

Python 3.9 or newer is sufficient; there are no third-party dependencies.

```sh
python3 autonomous_agent.py --selftest
python3 autonomous_agent.py
```

Optional environment variables:

```sh
AGENT_KEY_FILE=./demo/agent-key.hex \
AGENT_HANDLE=autonomous-demo \
python3 autonomous_agent.py
```

- `AGENT_PRIVATE_KEY`: 32-byte hex private key; takes precedence over a file
  and is never persisted by the agent.
- `AGENT_KEY_FILE`: generated/persisted key path (default `agent-key.hex` next
  to the script).
- `AGENT_HANDLE`: entry/submission handle (default `autonomous-agent`).
- `API_BASE_URL`: AIProve API origin (default `https://aiprove.fun`).

The normal run exits nonzero if an entry, required market lookup, or supported
prediction submission fails. Expected `needs build step` and ungroundable
prediction skips do not make the run fail.
