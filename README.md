# FiftyFifty Provably-Fair Verifier

A standalone, offline-capable verifier for FiftyFifty's 1v1 prediction games.
This tool re-derives any settled game's outcome from the committed seeds and
confirms the server seed matches its pre-game hash. It runs entirely in your
browser — no network calls, no FiftyFifty API dependency.

## Running locally

Web Crypto requires a secure context (HTTPS, `localhost`, or `file://` in most
modern browsers). The simplest options:

```bash
# Python
python3 -m http.server 8080

# Node
npx serve

# Or just open index.html directly in Chrome/Firefox/Safari — works on file:// too.
```

Then visit http://localhost:8080 and paste the audit data from a settled game.

## Where to find a game's audit data

In the FiftyFifty app, after a prediction game settles:

1. On the **Results** screen, click the **🔒 Provably Fair** badge.
2. The panel expands to show the game ID, hash, server seed, and both client seeds.
3. Either copy each value here, or click **Verify this game →** to open this
   tool with the fields prefilled via URL parameters.

## What it checks

1. **Hash check** — `SHA256(serverSeed) === storedHash`. If this fails, the
   server changed the seed after committing. Critical bug.
2. **Outcome derivation** — re-runs the same algorithm FiftyFifty uses
   server-side to compute the game outcome from the seeds. The result shown
   here should match what FiftyFifty stored for the game.

## The algorithm (v1, locked)

```
HMAC_SHA256(
  key   = serverSeed,
  data  = `${fairnessVersion}|${gameId}|${creatorSeed}|${opponentSeed}|${purposeTag}:${counter}`
)
```

- 32-byte HMAC blocks streamed; `counter` increments per block.
- Bytes read big-endian, converted to uniform integers via mask-and-reject
  (no modulo bias).
- Per-game purpose tags:
  - `number-guess:target`
  - `tile-reveal:board:creator` and `tile-reveal:board:opponent`
  - `blackjack:deck`
  - `plinko:balls`, `plinko:sudden`, `plinko:tiebreak`
- Canonical pre-shuffle deck order: ranks `2-A` × suits `h,d,c,s`, rank-major.

The full implementation is in `verify.js` — single file, no minification, no
bundler. Reading the source is the whole point of this tool existing.

## Trust this tool? Don't have to

- View Source → read `verify.js` directly. The algorithm is ~100 lines of plain
  JavaScript wrapping `crypto.subtle` (HMAC-SHA256 + SHA-256). The rest is form
  handling and result rendering.
- Re-implement the algorithm above in your favorite language. It's small enough
  to write in an afternoon. Run a settled game's seeds through your version,
  compare to what FiftyFifty stored, and to what this tool says.
- If your re-derivation disagrees with FiftyFifty's stored outcome, that's a
  critical bug — please report with the Game ID.

## License

MIT — fork it, audit it, republish it.
