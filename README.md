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

## Blackjack — dealing the verified deck

The verifier produces the shuffled 52-card deck deterministically from the
seeds. Mapping deck positions to hands is the game engine's responsibility,
not the crypto layer. To re-derive what each player was actually dealt:

**Initial deal (alternating, real-table order):**

```
deck[0] → creator  card 1
deck[1] → opponent card 1
deck[2] → creator  card 2
deck[3] → opponent card 2
```

The creator is the "right seat" — they always act first.

**During play (hit / stand):**

- Both players lock in their action simultaneously each round.
- When the round resolves, the creator's hit is processed before the opponent's,
  so the creator always pops the next card off the deck first if both hit.
- A 3-card hand uses `deck[4]` for whichever player hits first that round
  (creator if both did), `deck[5]` for the next hit, and so on.

**Push → re-deal (same shuffled deck, no new commitment):**

If both players stand at the same non-bust value, the engine does not refund
the stakes — it re-deals 4 fresh cards from the same shuffled deck:

```
After a round-1 push that consumed N cards through play, the round-2 deal is:
  deck[N+0] → creator  card 1
  deck[N+1] → opponent card 1
  deck[N+2] → creator  card 2
  deck[N+3] → opponent card 2
```

Re-deals are capped at 2 (round 1 + 2 re-deals = 3 hands max), then the game
goes to a coin flip. Double-bust is **not** a push and still settles as
both-lose. Side bets (Perfect 21) resolve once on the initial deal and are not
re-evaluated on re-deal.

**Coin-flip tiebreaker (after 3 pushes, or if the deck can't supply 4 cards):**

The next card popped from the deck decides the winner by suit color:

- Red (♥ / ♦) → creator wins
- Black (♣ / ♠) → opponent wins

In an unshuffled 52-card deck the split is exactly 26/26. If the deck happens
to be empty when the flip is needed (a theoretical edge case requiring an
enormous number of hits across three rounds), the engine falls back to a
deterministic hash of the game id; this fallback path is documented in the
engine source for completeness but is effectively unreachable in practice.

**Historical note.** Games settled before May 22 2026 used a block deal
(`deck[0..1]` → creator, `deck[2..3]` → opponent) instead of alternating. The
shuffled deck itself is unchanged — only which positions go to which player
differs. If you're re-verifying a game from that era, apply the block-deal
mapping; the deck the verifier shows is still authoritative.

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
