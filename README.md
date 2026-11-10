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
  - `tile-reveal:board:creator` and `tile-reveal:board:opponent` (round 1);
    Mines tie-break round N >= 2 appends `:round:N` and has one more bomb
    than the round before (capped at total tiles - 2); a tie in round 6 is
    settled by `tile-reveal:tiebreak` (0 = creator wins, 1 = opponent wins)
  - `blackjack:deck`
  - `plinko:balls`, `plinko:sudden`, `plinko:tiebreak`
  - `baccarat:shoe` (8 decks, one Fisher-Yates pass over all 416 cards)
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

## Baccarat — shoe, deal and recorded-result check

**Shoe.** `deckCount` (8; the game's `gameConfig.deck_count`, pinned to 8 by
the engine) back-to-back copies of the canonical 52-card deck, 416 cards in
rank-major order (`2h 2d 2c 2s 3h … As`, then again). The whole shoe is then
shuffled with one Fisher-Yates pass, descending:

```
for i = shoe.length - 1 down to 1:
  j = nextIntInRange(stream, 0, i)      // mask-and-reject, see above
  swap(shoe[i], shoe[j])
```

`stream` is the HMAC stream with purpose tag `baccarat:shoe`, keyed by the
server seed over
`1|${gameId}|${creatorClientSeed}|${opponentClientSeed}|baccarat:shoe:${counter}`.
Both client seeds and the game id are in every block, so the shoe is
independent of every other game and of the blackjack deck.

**Deal (Punto Banco), from the top of the shoe:** `shoe[0]` Player,
`shoe[1]` Banker, `shoe[2]` Player, `shoe[3]` Banker. Card values: A = 1,
2–9 face value, 10/J/Q/K = 0; a total is the sum mod 10.

- A **natural** (8 or 9 on two cards) on either side: nobody draws.
- Otherwise **Player** draws one card on 0–5 and stands on 6–7.
- If Player stood, **Banker** draws on 0–5 and stands on 6–7.
- If Player drew, Banker uses its two-card total and the **value** of
  Player's third card:

  | Banker | draws when Player's third card is |
  |---|---|
  | 0–2 | always |
  | 3 | anything but 8 |
  | 4 | 2–7 |
  | 5 | 4–7 |
  | 6 | 6–7 |
  | 7 | never |

- Third cards come off the shoe in that order: Player's (if any), then
  Banker's. Higher total wins; equal totals are a tie.

**Settlement** (both seats pick Banker or Player): a tie deal pushes both main
bets; opposite picks → the seat whose side won takes the pot
(`single_winner`); the same pick → `both_win_pot` if it hit, otherwise
`house_keeps_both` (`refund_both` if the game's `same_side_rule` is `refund`).
Games settled before 2026-08-12 used an earlier ruleset where Tie was a main
bet and a tie deal was not a push (`tie_winner`, `both_win_tie`); a record
with a Tie main bet is checked against that ruleset, and a record that only
matches it is flagged with a note rather than passed.

**Side bets** (gross payout = stake × (multiplier + 1), multipliers from the
game's `gameConfig.side_bets`, defaults in brackets): `tie` totals equal (8);
`player_pair` / `banker_pair` that hand's first two cards share a rank (11);
`either_pair` (5); `perfect_pair` either hand's first two cards are the same
rank and suit (25); `big` 5–6 cards dealt (0.54); `small` exactly 4 (1.5);
`dragon_7` Banker wins with a three-card 7 (40); `panda_8` Player wins with a
three-card 8 (25); `dragon_bonus` on a side: natural win 1:1, non-natural win
by 9/8/7/6/5/4 pays 30/10/6/4/2/1:1, a win by 1–3 loses, a tie with a natural
pushes.

**What the verifier checks.** With just the seeds (what the in-app link fills
in) it checks the hash and shows the shoe and the dealt hands. Paste the
game's fairness record (the JSON from
`GET /api/v1/prediction-games/:gameId/fairness`, or only its
`storedOutcome.winningNumber`) into **Recorded result** — or pass it as the
`record` URL parameter — and it also compares, field by field: the record's
game id, type, version and seeds; Player and Banker cards in order; both
totals; the outcome; the settlement type and winning seat; and every side
bet's won / push / gross payout. Main-bet amounts (pot, vig, the 5% Banker
commission) are not in the fairness record and are not checked.

**Games that can't be re-derived.** A record with `fairnessVersion: null` or
a missing seed has no commitment: the engine shuffled it with its crypto-RNG
fallback, so there is nothing to replay. The verifier says so instead of
reporting a mismatch. (Every Baccarat game since launch has been committed;
this covers incomplete rows.)

**Known-answer vectors.** `test-vectors/baccarat-vectors.json` lists seed sets
with the expected first 12 cards of the shoe, the SHA-256 of the full shoe
(cards joined with `,`), the dealt hands, totals, naturals and outcome — all
produced by the server code. For example, the all-zero server seed with
`1111…`/`2222…` client seeds and game id
`11111111-1111-4111-8111-111111111111` deals Player `6d Qc` (6), Banker
`Qd 7d` (7): Banker wins.

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
