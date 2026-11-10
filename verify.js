/**
 * FiftyFifty Provably-Fair Verifier — standalone, no framework.
 *
 * This file contains:
 *   1. A copy of the canonical fairness algorithm (locked at FAIRNESS_VERSION = 1).
 *      It is intentionally identical to fifty-frontend/src/utils/fairness.js
 *      and to the backend's fairness.ts. The shared test-vectors/fairness-vectors.json
 *      file is the spec — three implementations, one truth. Baccarat (shoe,
 *      Punto Banco deal, settlement, side bets) mirrors the backend's
 *      fairness.ts + baccaratEngine.ts; its known-answer vectors are in
 *      test-vectors/baccarat-vectors.json. Poker (deck, Hold'em deal with
 *      burns, hand evaluator) mirrors fairness.ts + pokerEngine.ts + holdem.ts;
 *      its vectors are in test-vectors/poker-vectors.json.
 *   2. A small UI driver that reads the form, runs the derivation, and renders
 *      the result.
 *
 * No imports from FiftyFifty's app or API. Open the page, paste data, get a result.
 * Reading the source is the whole point of this file existing.
 */

// ===========================================================================
// CRYPTO HELPERS
// ===========================================================================

const HEX_RE = /^[0-9a-fA-F]*$/;
const HEX_64_RE = /^[0-9a-f]{64}$/;
const TEXT_ENCODER = new TextEncoder();

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !HEX_RE.test(hex)) {
    throw new Error('hexToBytes: input must be an even-length hex string');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, '0');
  }
  return s;
}

async function sha256Hex(bytes) {
  const buf = await crypto.subtle.digest('SHA-256', bytes);
  return bytesToHex(new Uint8Array(buf));
}

// ===========================================================================
// FAIRNESS ALGORITHM (v1 — locked)
// ===========================================================================

const FAIRNESS_VERSION = 1;

const CANONICAL_RANKS = ['2', '3', '4', '5', '6', '7', '8', '9', 'T', 'J', 'Q', 'K', 'A'];
const CANONICAL_SUITS = ['h', 'd', 'c', 's'];

function validateClientSeed(seed) {
  if (typeof seed !== 'string' || !HEX_64_RE.test(seed)) {
    throw new Error('Client seed must be exactly 64 lowercase hex characters');
  }
}

function buildMessage(input, purposeTag) {
  validateClientSeed(input.creatorClientSeed);
  validateClientSeed(input.opponentClientSeed);
  if (!input.gameId) throw new Error('gameId is required');
  if (!purposeTag) throw new Error('purposeTag is required');
  return [
    input.fairnessVersion,
    input.gameId,
    input.creatorClientSeed,
    input.opponentClientSeed,
    purposeTag
  ].join('|');
}

async function* hmacStream(serverSeedBytes, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    serverSeedBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  let counter = 0;
  while (true) {
    const data = TEXT_ENCODER.encode(`${message}:${counter}`);
    const sig = await crypto.subtle.sign('HMAC', key, data);
    const block = new Uint8Array(sig);
    for (let i = 0; i < block.length; i++) yield block[i];
    counter += 1;
  }
}

async function nextIntInRange(stream, min, max) {
  if (!Number.isInteger(min) || !Number.isInteger(max)) {
    throw new Error(`min/max must be integers: min=${min}, max=${max}`);
  }
  if (max < min) throw new Error(`max < min: max=${max}, min=${min}`);
  const range = max - min + 1;
  if (range === 1) return min;
  const bitsNeeded = Math.ceil(Math.log2(range));
  const bytesNeeded = Math.ceil(bitsNeeded / 8);
  const mask = (1 << bitsNeeded) - 1;
  for (let attempt = 0; attempt < 1024; attempt++) {
    let v = 0;
    for (let i = 0; i < bytesNeeded; i++) {
      const next = await stream.next();
      if (next.done || typeof next.value !== 'number') {
        throw new Error('hmacStream exhausted unexpectedly');
      }
      v = (v << 8) | next.value;
    }
    v = v & mask;
    if (v < range) return min + v;
  }
  throw new Error('nextIntInRange exceeded 1024 rejection attempts');
}

async function deriveNumberGuessTarget(input, config) {
  const seed = hexToBytes(input.serverSeed);
  const stream = hmacStream(seed, buildMessage(input, 'number-guess:target'));
  return nextIntInRange(stream, config.min, config.max);
}

// Mines tie-break rounds: a tied round is replayed on fresh boards with one
// more bomb, up to TILE_REVEAL_MAX_ROUNDS rounds; a tie in the last round is
// settled by a coin flip. Round 1 keeps the original purpose tags, round
// N >= 2 appends `:round:N`. The flip uses its own tag, `tile-reveal:tiebreak`.
const TILE_REVEAL_MAX_ROUNDS = 6;

function tileBoardPurposeTag(role, round = 1) {
  if (!Number.isInteger(round) || round < 1) throw new Error(`Invalid tile-reveal round: ${round}`);
  const base = `tile-reveal:board:${role}`;
  return round === 1 ? base : `${base}:round:${round}`;
}

// Bombs on round N: the configured count for round 1, one more per replay,
// capped so at least two safe tiles remain (matches the backend).
function bombCountForRound(totalTiles, baseBombs, round) {
  return Math.max(1, Math.min(baseBombs + round - 1, totalTiles - 2));
}

async function deriveTileBoards(input, config, round = 1) {
  const seed = hexToBytes(input.serverSeed);
  return {
    creator: await deriveBombBoard(seed, buildMessage(input, tileBoardPurposeTag('creator', round)), config),
    opponent: await deriveBombBoard(seed, buildMessage(input, tileBoardPurposeTag('opponent', round)), config)
  };
}

async function deriveTileRevealTiebreak(input) {
  const seed = hexToBytes(input.serverSeed);
  const stream = hmacStream(seed, buildMessage(input, 'tile-reveal:tiebreak'));
  return nextIntInRange(stream, 0, 1);
}

async function deriveBombBoard(seedBytes, message, config) {
  if (config.bombCount < 0 || config.bombCount > config.totalTiles) {
    throw new Error(`Invalid bomb config: bombCount=${config.bombCount}, totalTiles=${config.totalTiles}`);
  }
  const stream = hmacStream(seedBytes, message);
  const board = new Array(config.totalTiles).fill(0);
  const available = [];
  for (let i = 0; i < config.totalTiles; i++) available.push(i);
  for (let i = 0; i < config.bombCount; i++) {
    const idx = await nextIntInRange(stream, 0, available.length - 1);
    board[available[idx]] = 1;
    available.splice(idx, 1);
  }
  return board;
}

function createCanonicalDeck() {
  const deck = [];
  for (const rank of CANONICAL_RANKS) {
    for (const suit of CANONICAL_SUITS) deck.push(rank + suit);
  }
  return deck;
}

async function deriveShuffledDeck(input) {
  const seed = hexToBytes(input.serverSeed);
  const stream = hmacStream(seed, buildMessage(input, 'blackjack:deck'));
  const deck = createCanonicalDeck();
  for (let i = deck.length - 1; i > 0; i--) {
    const j = await nextIntInRange(stream, 0, i);
    [deck[i], deck[j]] = [deck[j], deck[i]];
  }
  return deck;
}

// ---------------------------------------------------------------------------
// BACCARAT
//
// Mirrors the backend's deriveBaccaratShoe (engines/fairness.ts) and the pure
// rule functions in engines/baccaratEngine.ts: dealPuntoBanco,
// classifySettlement and resolveSideBet. Keep these line-for-line with the
// engine; the fidelity check compares them against the server code.
// ---------------------------------------------------------------------------

// deck_count is pinned to 8 by the engine's validateConfig and has never
// been anything else; a game's own gameConfig.deck_count wins if present.
const BACCARAT_DEFAULT_DECK_COUNT = 8;

// Shoe: deckCount back-to-back canonical 52-card decks, then a Fisher-Yates
// descending swap over the whole shoe, drawn from the `baccarat:shoe` stream.
async function deriveBaccaratShoe(input, deckCount) {
  if (!Number.isInteger(deckCount) || deckCount < 1 || deckCount > 8) {
    throw new Error(`Invalid deckCount: ${deckCount}`);
  }
  const seed = hexToBytes(input.serverSeed);
  const stream = hmacStream(seed, buildMessage(input, 'baccarat:shoe'));
  const shoe = [];
  for (let d = 0; d < deckCount; d++) shoe.push(...createCanonicalDeck());
  for (let i = shoe.length - 1; i > 0; i--) {
    const j = await nextIntInRange(stream, 0, i);
    [shoe[i], shoe[j]] = [shoe[j], shoe[i]];
  }
  return shoe;
}

/** A=1, 2-9 pip value, T/J/Q/K=0. */
function baccaratCardValue(card) {
  const rank = card[0];
  if (rank === 'A') return 1;
  if (rank === 'T' || rank === 'J' || rank === 'Q' || rank === 'K') return 0;
  return parseInt(rank, 10);
}

/** Modulo-10 hand total. */
function baccaratHandScore(hand) {
  return hand.reduce((sum, card) => sum + baccaratCardValue(card), 0) % 10;
}

/**
 * One Punto Banco round from the top of the shoe: P, B, P, B; a natural
 * (8 or 9 on two cards) on either side stops all drawing; otherwise Player
 * draws on 0-5 and stands on 6-7, and Banker follows the standard tableau,
 * keyed on Banker's two-card total and the VALUE of Player's third card.
 * The extra fields (player/bankerTwo, playerThirdValue, drew flags) only
 * explain the deal in the UI; they don't change it.
 */
function dealPuntoBanco(shoe) {
  if (shoe.length < 6) throw new Error(`Shoe too small to deal: ${shoe.length} cards`);
  let idx = 0;
  const draw = () => shoe[idx++];

  const playerHand = [draw()];
  const bankerHand = [draw()];
  playerHand.push(draw());
  bankerHand.push(draw());

  const playerTwo = baccaratHandScore(playerHand);
  const bankerTwo = baccaratHandScore(bankerHand);
  const playerNatural = playerTwo >= 8;
  const bankerNatural = bankerTwo >= 8;
  let playerThirdValue = null;

  if (!playerNatural && !bankerNatural) {
    if (playerTwo <= 5) {
      const card = draw();
      playerHand.push(card);
      playerThirdValue = baccaratCardValue(card);
    }
    let bankerDraws;
    if (playerThirdValue === null) {
      // Player stood: Banker draws on 0-5, stands on 6-7.
      bankerDraws = bankerTwo <= 5;
    } else {
      const v = playerThirdValue;
      if (bankerTwo <= 2) bankerDraws = true;
      else if (bankerTwo === 3) bankerDraws = v !== 8;
      else if (bankerTwo === 4) bankerDraws = v >= 2 && v <= 7;
      else if (bankerTwo === 5) bankerDraws = v >= 4 && v <= 7;
      else if (bankerTwo === 6) bankerDraws = v === 6 || v === 7;
      else bankerDraws = false; // 7 stands
    }
    if (bankerDraws) bankerHand.push(draw());
  }

  const playerScore = baccaratHandScore(playerHand);
  const bankerScore = baccaratHandScore(bankerHand);
  const outcome =
    playerScore > bankerScore ? 'player' :
    bankerScore > playerScore ? 'banker' : 'tie';

  return {
    playerHand, bankerHand, playerScore, bankerScore, playerNatural, bankerNatural, outcome,
    playerTwo, bankerTwo, playerThirdValue
  };
}

/**
 * Head-to-head settlement under the current ruleset (Tie is a side bet, not
 * a main bet, since 2026-08-12). Returns the winner as a seat role, the same
 * way the fairness record names it.
 */
function classifyBaccaratSettlement(creatorBet, opponentBet, outcome, sameSideRule) {
  if (outcome === 'tie') return { type: 'tie_push', winner: null };
  if (creatorBet === opponentBet) {
    if (sameSideRule === 'refund') return { type: 'refund_both', winner: null };
    return outcome === creatorBet
      ? { type: 'both_win_pot', winner: null }
      : { type: 'house_keeps_both', winner: null };
  }
  const creatorHit = creatorBet === outcome;
  const opponentHit = opponentBet === outcome;
  if (!creatorHit && !opponentHit) return { type: 'house_keeps_both', winner: null };
  return { type: 'single_winner', winner: creatorHit ? 'creator' : 'opponent' };
}

/**
 * Settlement under the ruleset before 2026-08-12, when Tie was a main-bet
 * option and a tie deal was not a push. Kept so games from that period still
 * check out; the deal itself was the same.
 */
function classifyBaccaratSettlementPreAug2026(creatorBet, opponentBet, outcome, sameSideRule) {
  if (creatorBet === opponentBet) {
    if (creatorBet === 'tie') {
      return outcome === 'tie'
        ? { type: 'both_win_tie', winner: null }
        : { type: 'house_keeps_both', winner: null };
    }
    if (sameSideRule === 'refund') return { type: 'refund_both', winner: null };
    return outcome === creatorBet
      ? { type: 'both_win_pot', winner: null }
      : { type: 'house_keeps_both', winner: null };
  }
  const creatorHit = creatorBet === outcome;
  const opponentHit = opponentBet === outcome;
  if (!creatorHit && !opponentHit) return { type: 'house_keeps_both', winner: null };
  const winningBet = creatorHit ? creatorBet : opponentBet;
  return {
    type: winningBet === 'tie' ? 'tie_winner' : 'single_winner',
    winner: creatorHit ? 'creator' : 'opponent'
  };
}

// Dragon Bonus margin table (X:1), frozen in the engine since launch.
const BACCARAT_DRAGON_BONUS_PAY_TABLE = {
  natural_win: 1, margin_9: 30, margin_8: 10, margin_7: 6, margin_6: 4, margin_5: 2, margin_4: 1
};

// The engine's default side-bet multipliers (X:1). Used only when the pasted
// record doesn't carry the game's own gameConfig.
const BACCARAT_DEFAULT_SIDE_BETS = {
  tie: { payout_multiplier: 8 },
  player_pair: { payout_multiplier: 11 },
  banker_pair: { payout_multiplier: 11 },
  either_pair: { payout_multiplier: 5 },
  perfect_pair: { payout_multiplier: 25 },
  big: { payout_multiplier: 0.54 },
  small: { payout_multiplier: 1.5 },
  dragon_bonus: { payout_multiplier: 30 },
  dragon_7: { payout_multiplier: 40 },
  panda_8: { payout_multiplier: 25 }
};

function roundMoney(amount) {
  return Math.round(amount * 100) / 100;
}

/**
 * Resolve one side bet against the deal: { won, pushed, payout }, payout
 * being the GROSS amount (stake + winnings) the engine records.
 * `sideBets` is the game's config.side_bets (multipliers per type).
 */
function resolveBaccaratSideBet(bet, deal, sideBets) {
  const lose = { won: false, pushed: false, payout: 0 };
  const totalCards = deal.playerHand.length + deal.bankerHand.length;
  const multiplier = sideBets?.[bet.type]?.payout_multiplier ?? 0;
  const win = (mult) => ({ won: true, pushed: false, payout: roundMoney(bet.amount * (mult + 1)) });
  const isPair = (h) => h.length >= 2 && h[0][0] === h[1][0];
  const isPerfectPair = (h) => h.length >= 2 && h[0] === h[1];

  switch (bet.type) {
    case 'tie':
      return deal.outcome === 'tie' ? win(multiplier) : lose;
    case 'player_pair':
      return isPair(deal.playerHand) ? win(multiplier) : lose;
    case 'banker_pair':
      return isPair(deal.bankerHand) ? win(multiplier) : lose;
    case 'either_pair':
      return (isPair(deal.playerHand) || isPair(deal.bankerHand)) ? win(multiplier) : lose;
    case 'perfect_pair':
      return (isPerfectPair(deal.playerHand) || isPerfectPair(deal.bankerHand)) ? win(multiplier) : lose;
    case 'big':
      return totalCards >= 5 ? win(multiplier) : lose;
    case 'small':
      return totalCards === 4 ? win(multiplier) : lose;
    case 'dragon_7':
      return (deal.outcome === 'banker' && deal.bankerHand.length === 3 && deal.bankerScore === 7)
        ? win(multiplier) : lose;
    case 'panda_8':
      return (deal.outcome === 'player' && deal.playerHand.length === 3 && deal.playerScore === 8)
        ? win(multiplier) : lose;
    case 'dragon_bonus': {
      const side = bet.side;
      const table = BACCARAT_DRAGON_BONUS_PAY_TABLE;
      if (deal.outcome === 'tie') {
        // A tie with a natural pushes (stake back); any other tie loses.
        return (deal.playerNatural || deal.bankerNatural) ? { ...lose, pushed: true } : lose;
      }
      if (deal.outcome !== side) return lose;
      const sideNatural = side === 'player' ? deal.playerNatural : deal.bankerNatural;
      if (sideNatural) return win(table.natural_win);
      const margin = Math.abs(deal.playerScore - deal.bankerScore);
      if (margin >= 9) return win(table.margin_9);
      if (margin === 8) return win(table.margin_8);
      if (margin === 7) return win(table.margin_7);
      if (margin === 6) return win(table.margin_6);
      if (margin === 5) return win(table.margin_5);
      if (margin === 4) return win(table.margin_4);
      return lose; // a non-natural win by 1-3 loses
    }
    default:
      return lose;
  }
}

// ---------------------------------------------------------------------------
// RECORDED RESULT (optional): the game's fairness JSON, as served by
// GET /api/v1/prediction-games/:gameId/fairness, or just its
// storedOutcome.winningNumber. Pure parsing, no network.
// ---------------------------------------------------------------------------

function parseJsonMaybeTwice(value) {
  let v = value;
  for (let i = 0; i < 2 && typeof v === 'string'; i++) v = JSON.parse(v);
  return v;
}

/**
 * Returns { meta, deal, winner } where meta is the fairness object (or null
 * when only a winningNumber was pasted), deal is the parsed winningNumber
 * (or null) and winner is storedOutcome.winner (undefined when absent).
 */
function parseRecordedResult(text) {
  const trimmed = (text || '').trim();
  if (!trimmed) return null;
  let obj;
  try {
    obj = parseJsonMaybeTwice(trimmed);
  } catch (err) {
    throw new Error(`Recorded result is not valid JSON: ${err.message}`);
  }
  if (!obj || typeof obj !== 'object') throw new Error('Recorded result must be a JSON object.');
  if (obj.fairness && typeof obj.fairness === 'object') obj = obj.fairness;

  if (obj.storedOutcome !== undefined || obj.serverSeedHash !== undefined) {
    const stored = obj.storedOutcome || {};
    let deal = null;
    if (stored.winningNumber != null) {
      try {
        deal = parseJsonMaybeTwice(stored.winningNumber);
      } catch (err) {
        throw new Error(`storedOutcome.winningNumber is not valid JSON: ${err.message}`);
      }
    }
    return { meta: obj, deal, winner: stored.winner };
  }
  if (obj.playerHand !== undefined || obj.outcome !== undefined) {
    return { meta: null, deal: obj, winner: undefined };
  }
  throw new Error('Recorded result is neither a fairness record nor a game\'s winningNumber.');
}

/**
 * Why a Baccarat record can't be re-derived, or null if it can. Games with no
 * provably-fair commitment (fairnessVersion null, or a seed missing) were
 * shuffled by the engine's legacy crypto-RNG fallback, which leaves nothing to
 * replay — that is not a mismatch.
 */
function baccaratRecordUnverifiableReason(rec) {
  const m = rec?.meta;
  if (!m) return null;
  if (m.fairnessVersion == null || !m.serverSeedHash || !m.creatorClientSeed || !m.opponentClientSeed) {
    return 'legacy';
  }
  if (!m.serverSeed) return 'unrevealed';
  return null;
}

/**
 * Compare a derived deal with a recorded one. Each check is
 * { label, status: 'pass' | 'fail' | 'note', expected, recorded, note? }.
 * Only fields the record actually carries are checked.
 */
/** The record's own id, type, version and seeds against the form's inputs. */
function compareRecordMeta(meta, input, gameType, add) {
  if (meta.gameId !== undefined) add('Record game ID', meta.gameId === input.gameId, input.gameId, meta.gameId);
  if (meta.gameType !== undefined) add('Record game type', meta.gameType === gameType, gameType, meta.gameType);
  if (meta.fairnessVersion !== undefined) {
    add('Algorithm version', meta.fairnessVersion === FAIRNESS_VERSION, FAIRNESS_VERSION, meta.fairnessVersion);
  }
  const same = (a, b) => String(a || '').toLowerCase() === String(b || '').toLowerCase();
  if (meta.serverSeed) add('Record server seed', same(meta.serverSeed, input.serverSeed), input.serverSeed, meta.serverSeed);
  if (meta.creatorClientSeed) add('Record creator seed', same(meta.creatorClientSeed, input.creatorClientSeed), input.creatorClientSeed, meta.creatorClientSeed);
  if (meta.opponentClientSeed) add('Record opponent seed', same(meta.opponentClientSeed, input.opponentClientSeed), input.opponentClientSeed, meta.opponentClientSeed);
}

function compareBaccaratRecord(derived, rec, input) {
  const checks = [];
  const add = (label, ok, expected, recorded, note) =>
    checks.push({ label, status: ok ? 'pass' : 'fail', expected, recorded, note });
  const meta = rec.meta;
  const deal = rec.deal;
  const fmt = (v) => (Array.isArray(v) ? v.join(' ') : v === null ? 'null' : v === undefined ? '—' : String(v));

  if (meta) compareRecordMeta(meta, input, 'baccarat', add);

  if (!deal) return checks;
  const d = derived.deal;
  const sameArr = (a, b) => Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => x === b[i]);

  if (deal.playerHand !== undefined) add('Player cards', sameArr(d.playerHand, deal.playerHand), fmt(d.playerHand), fmt(deal.playerHand));
  if (deal.bankerHand !== undefined) add('Banker cards', sameArr(d.bankerHand, deal.bankerHand), fmt(d.bankerHand), fmt(deal.bankerHand));
  if (deal.playerScore !== undefined) add('Player total', d.playerScore === deal.playerScore, d.playerScore, fmt(deal.playerScore));
  if (deal.bankerScore !== undefined) add('Banker total', d.bankerScore === deal.bankerScore, d.bankerScore, fmt(deal.bankerScore));
  if (deal.outcome !== undefined) add('Outcome', d.outcome === deal.outcome, d.outcome, fmt(deal.outcome));

  // Settlement: a rules function of the two main bets and the outcome.
  const creatorBet = deal.creatorBet;
  const opponentBet = deal.opponentBet;
  const sameSideRule = meta?.gameConfig?.same_side_rule ?? 'both_win';
  let expectedSettlement = null;
  if (creatorBet && opponentBet) {
    const current = classifyBaccaratSettlement(creatorBet, opponentBet, d.outcome, sameSideRule);
    const earlier = classifyBaccaratSettlementPreAug2026(creatorBet, opponentBet, d.outcome, sameSideRule);
    const recordedSettlement = deal.settlement || null;
    // New records name the winner `winner`; older ones kept `winnerUserId`,
    // which the fairness endpoint relabels to the seat role.
    const recordedWinner = recordedSettlement
      ? (recordedSettlement.winner !== undefined ? recordedSettlement.winner : recordedSettlement.winnerUserId ?? null)
      : undefined;
    const matches = (s) => recordedSettlement && s.type === recordedSettlement.type && s.winner === recordedWinner;
    const legacyBet = creatorBet === 'tie' || opponentBet === 'tie';
    const shown = (s) => `${s.type}${s.winner ? ` · ${s.winner} wins` : ''}`;
    const recShown = recordedSettlement ? shown({ type: recordedSettlement.type, winner: recordedWinner }) : '—';
    if (legacyBet) {
      expectedSettlement = earlier;
      add('Settlement', matches(earlier), shown(earlier), recShown,
        'A Tie main bet means this game used the ruleset before 2026-08-12.');
    } else if (matches(current)) {
      expectedSettlement = current;
      add('Settlement', true, shown(current), recShown);
    } else if (matches(earlier)) {
      expectedSettlement = earlier;
      checks.push({
        label: 'Settlement', status: 'note', expected: shown(current), recorded: recShown,
        note: 'Matches the ruleset used before 2026-08-12 (a tie deal was not a push then). Correct only if the game settled before that change.'
      });
    } else {
      expectedSettlement = current;
      add('Settlement', false, shown(current), recShown);
    }
  }

  if (rec.winner !== undefined) {
    const expectedWinner = expectedSettlement ? expectedSettlement.winner : undefined;
    if (expectedWinner !== undefined) add('Winning seat', rec.winner === expectedWinner, fmt(expectedWinner), fmt(rec.winner));
  }

  const sideBetConfig = meta?.gameConfig?.side_bets || BACCARAT_DEFAULT_SIDE_BETS;
  const payNote = meta?.gameConfig?.side_bets ? null : 'Payout checked against the default pay table (the record has no gameConfig).';
  for (const seat of ['creator', 'opponent']) {
    const bets = deal[`${seat}SideBets`];
    if (!Array.isArray(bets)) continue;
    for (const bet of bets) {
      const r = resolveBaccaratSideBet(bet, d, sideBetConfig);
      const name = `${seat} side bet · ${bet.type}${bet.side ? ` (${bet.side})` : ''} · ${bet.amount}`;
      const exp = r.won ? `won · pays ${r.payout}` : r.pushed ? 'push' : 'lost';
      let got = bet.won ? `won · pays ${bet.payout}` : bet.pushed ? 'push' : 'lost';
      if (!bet.won && bet.payout) got += ` · pays ${bet.payout}`;
      // The engine records payout 0 for a lost or pushed bet.
      const ok = !!bet.won === r.won && !!bet.pushed === r.pushed && bet.payout === r.payout;
      add(name, ok, exp, got, r.won ? payNote : null);
    }
  }
  return checks;
}

// ---------------------------------------------------------------------------
// POKER (1v1 Texas Hold'em, one hand per game)
//
// Mirrors the backend's derivePokerDeck (engines/fairness.ts), the deal in
// engines/pokerEngine.ts (initializeGameState, burnsTakenBefore,
// dealCommunityTo) and the hand evaluator in engines/holdem.ts. Keep these
// line-for-line with the engine; the fidelity check compares them against the
// server code.
// ---------------------------------------------------------------------------

// Deck: the canonical 52-card deck, one Fisher-Yates pass, descending, drawn
// from the `poker:deck` stream. Same shuffle as blackjack, different tag, so
// a poker deck and a blackjack deck from the same seeds are unrelated.
async function derivePokerDeck(input) {
  const seed = hexToBytes(input.serverSeed);
  const stream = hmacStream(seed, buildMessage(input, 'poker:deck'));
  const deck = createCanonicalDeck();
  for (let i = deck.length - 1; i > 0; i--) {
    const j = await nextIntInRange(stream, 0, i);
    [deck[i], deck[j]] = [deck[j], deck[i]];
  }
  return deck;
}

// Two hole cards each, dealt alternating before any board card.
const POKER_HOLE_CARDS_DEALT = 4;
const POKER_STREETS = [
  { name: 'flop', cards: [0, 1, 2] },
  { name: 'turn', cards: [3] },
  { name: 'river', cards: [4] }
];

// Hands dealt from 2026-10-04 (backend 82447d1) burn one card before the flop,
// the turn and the river; earlier hands dealt the board straight after the
// hole cards. The engine stamps the mapping on each hand at the deal.
const POKER_BURNS_SINCE = '2026-10-05T04:25:49Z';

/** Cards burned by the time the board holds `dealt` cards (engine's burnsTakenBefore). */
function pokerBurnsTakenBefore(dealt) {
  if (dealt < 3) return 1; // flop
  if (dealt === 3) return 2; // turn
  return 3; // river
}

/** Deck index of board card k (0-4), as the engine's dealCommunityTo computes it. */
function pokerBoardIndex(k, burnCards) {
  const burns = burnCards ? pokerBurnsTakenBefore(k) : 0;
  return POKER_HOLE_CARDS_DEALT + burns + k;
}

/**
 * The whole deal from a derived deck. Creator gets deck[0] and deck[2],
 * opponent deck[1] and deck[3]. With burns: 4 burn, 5-7 flop, 8 burn, 9 turn,
 * 10 burn, 11 river. Without: 4-8 board.
 */
function dealPokerHand(deck, burnCards) {
  if (deck.length < 12) throw new Error(`Deck too small to deal: ${deck.length} cards`);
  const boardIndex = [0, 1, 2, 3, 4].map(k => pokerBoardIndex(k, burnCards));
  const burns = burnCards
    ? POKER_STREETS.map(s => {
        const index = pokerBoardIndex(s.cards[0], true) - 1;
        return { before: s.name, index, card: deck[index] };
      })
    : [];
  return {
    burnCards,
    creatorHole: [deck[0], deck[2]],
    opponentHole: [deck[1], deck[3]],
    boardIndex,
    board: boardIndex.map(i => deck[i]),
    burns
  };
}

// ---- Hand evaluator (port of engines/holdem.ts) ----

const HOLDEM_RANK_VALUE = {
  '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
  T: 10, J: 11, Q: 12, K: 13, A: 14
};
const HOLDEM_SUITS = new Set(['h', 'd', 'c', 's']);
const HOLDEM_CLASS_RANK = {
  high_card: 1, pair: 2, two_pair: 3, three_of_a_kind: 4, straight: 5,
  flush: 6, full_house: 7, four_of_a_kind: 8, straight_flush: 9
};
const HOLDEM_CLASS_NAME = {
  high_card: 'High card', pair: 'Pair', two_pair: 'Two pair', three_of_a_kind: 'Three of a kind',
  straight: 'Straight', flush: 'Flush', full_house: 'Full house', four_of_a_kind: 'Four of a kind',
  straight_flush: 'Straight flush'
};
const HOLDEM_RANK_NAME = {
  2: 'Two', 3: 'Three', 4: 'Four', 5: 'Five', 6: 'Six', 7: 'Seven', 8: 'Eight',
  9: 'Nine', 10: 'Ten', 11: 'Jack', 12: 'Queen', 13: 'King', 14: 'Ace'
};
const HOLDEM_RANK_NAME_PLURAL = {
  2: 'Twos', 3: 'Threes', 4: 'Fours', 5: 'Fives', 6: 'Sixes', 7: 'Sevens',
  8: 'Eights', 9: 'Nines', 10: 'Tens', 11: 'Jacks', 12: 'Queens', 13: 'Kings', 14: 'Aces'
};
// Rank values run 2..14, so base 15 gives each tiebreaker its own digit and
// `rank` compares [classRank, t0..t4] lexicographically.
const HOLDEM_TB_BASE = 15;
const HOLDEM_TB_SLOTS = 5;

function holdemRankValue(card) {
  return HOLDEM_RANK_VALUE[card[0]];
}

function assertHoldemCard(card, where) {
  if (typeof card !== 'string' || card.length !== 2
      || HOLDEM_RANK_VALUE[card[0]] === undefined || !HOLDEM_SUITS.has(card[1])) {
    throw new Error(`Invalid card in ${where}: ${String(card)}`);
  }
}

function holdemPackRank(classRank, tiebreakers) {
  let value = classRank;
  for (let i = 0; i < HOLDEM_TB_SLOTS; i++) value = value * HOLDEM_TB_BASE + (tiebreakers[i] ?? 0);
  return value;
}

function holdemPadTiebreakers(tiebreakers) {
  const out = tiebreakers.slice(0, HOLDEM_TB_SLOTS);
  while (out.length < HOLDEM_TB_SLOTS) out.push(0);
  return out;
}

/** Top card of the highest straight among distinct values (desc), 0 if none. The wheel tops out at 5. */
function holdemStraightHigh(distinctDesc) {
  const values = distinctDesc.includes(14) ? [...distinctDesc, 1] : distinctDesc;
  let run = 1;
  for (let i = 1; i < values.length; i++) {
    if (values[i] === values[i - 1] - 1) {
      run++;
      if (run >= 5) return values[i - 4];
    } else {
      run = 1;
    }
  }
  return 0;
}

function holdemLabel(handClass, tb) {
  const t0 = tb[0];
  const t1 = tb[1];
  switch (handClass) {
    case 'straight_flush': return t0 === 14 ? 'Royal Flush' : `Straight Flush, ${HOLDEM_RANK_NAME[t0]} high`;
    case 'four_of_a_kind': return `Four of a Kind, ${HOLDEM_RANK_NAME_PLURAL[t0]}`;
    case 'full_house': return `Full House, ${HOLDEM_RANK_NAME_PLURAL[t0]} full of ${HOLDEM_RANK_NAME_PLURAL[t1]}`;
    case 'flush': return `Flush, ${HOLDEM_RANK_NAME[t0]} high`;
    case 'straight': return `Straight, ${HOLDEM_RANK_NAME[t0]} high`;
    case 'three_of_a_kind': return `Three of a Kind, ${HOLDEM_RANK_NAME_PLURAL[t0]}`;
    case 'two_pair': return `Two Pair, ${HOLDEM_RANK_NAME_PLURAL[t0]} and ${HOLDEM_RANK_NAME_PLURAL[t1]}`;
    case 'pair': return `Pair of ${HOLDEM_RANK_NAME_PLURAL[t0]}`;
    default: return `High Card, ${HOLDEM_RANK_NAME[t0]}`;
  }
}

/** Exactly five validated cards → { handClass, tiebreakers, cards (significance order) }. */
function holdemEvaluateFive(cards) {
  const byRank = new Map();
  const bySuit = new Map();
  for (const card of cards) {
    const value = holdemRankValue(card);
    const suit = card[1];
    if (byRank.has(value)) byRank.get(value).push(card); else byRank.set(value, [card]);
    if (bySuit.has(suit)) bySuit.get(suit).push(card); else bySuit.set(suit, [card]);
  }
  // Count desc, then value desc: the kicker order for every paired class.
  const groups = [...byRank.entries()]
    .map(([value, group]) => ({ value, count: group.length, cards: group }))
    .sort((a, b) => (b.count - a.count) || (b.value - a.value));
  const distinctDesc = groups.map(g => g.value).sort((a, b) => b - a);
  const isFlush = bySuit.size === 1;
  const straightTop = holdemStraightHigh(distinctDesc);
  const orderByRun = (top) => {
    const wanted = top === 5 ? [5, 4, 3, 2, 14] : [top, top - 1, top - 2, top - 3, top - 4];
    return wanted.map(value => byRank.get(value)[0]);
  };

  if (isFlush && straightTop > 0) {
    return { handClass: 'straight_flush', tiebreakers: holdemPadTiebreakers([straightTop]), cards: orderByRun(straightTop) };
  }
  const ordered = groups.flatMap(g => g.cards);
  if (groups[0]?.count === 4) {
    return { handClass: 'four_of_a_kind', tiebreakers: holdemPadTiebreakers([groups[0].value, groups[1]?.value ?? 0]), cards: ordered };
  }
  if (groups[0]?.count === 3 && groups[1]?.count === 2) {
    return { handClass: 'full_house', tiebreakers: holdemPadTiebreakers([groups[0].value, groups[1].value]), cards: ordered };
  }
  if (isFlush) {
    return {
      handClass: 'flush',
      tiebreakers: holdemPadTiebreakers(distinctDesc),
      cards: [...cards].sort((a, b) => holdemRankValue(b) - holdemRankValue(a))
    };
  }
  if (straightTop > 0) {
    return { handClass: 'straight', tiebreakers: holdemPadTiebreakers([straightTop]), cards: orderByRun(straightTop) };
  }
  if (groups[0]?.count === 3) {
    return {
      handClass: 'three_of_a_kind',
      tiebreakers: holdemPadTiebreakers([groups[0].value, groups[1]?.value ?? 0, groups[2]?.value ?? 0]),
      cards: ordered
    };
  }
  if (groups[0]?.count === 2 && groups[1]?.count === 2) {
    return {
      handClass: 'two_pair',
      tiebreakers: holdemPadTiebreakers([groups[0].value, groups[1].value, groups[2]?.value ?? 0]),
      cards: ordered
    };
  }
  if (groups[0]?.count === 2) {
    return {
      handClass: 'pair',
      tiebreakers: holdemPadTiebreakers([groups[0].value, groups[1]?.value ?? 0, groups[2]?.value ?? 0, groups[3]?.value ?? 0]),
      cards: ordered
    };
  }
  return { handClass: 'high_card', tiebreakers: holdemPadTiebreakers(distinctDesc), cards: ordered };
}

function holdemHandResult(evaluated) {
  const classRank = HOLDEM_CLASS_RANK[evaluated.handClass];
  return {
    handClass: evaluated.handClass,
    classRank,
    rank: holdemPackRank(classRank, evaluated.tiebreakers),
    cards: evaluated.cards,
    tiebreakers: evaluated.tiebreakers,
    label: holdemLabel(evaluated.handClass, evaluated.tiebreakers)
  };
}

// All 21 five-card subsets of seven cards, in the engine's order.
const HOLDEM_FIVE_OF_SEVEN = (() => {
  const combos = [];
  for (let a = 0; a < 7; a++)
    for (let b = a + 1; b < 7; b++)
      for (let c = b + 1; c < 7; c++)
        for (let d = c + 1; d < 7; d++)
          for (let e = d + 1; e < 7; e++) combos.push([a, b, c, d, e]);
  return combos;
})();

/** Best five of 2 hole + 5 board cards, exhaustive over all 21 subsets (first strictly best wins). */
function evaluateHoldem(hole, community) {
  if (!Array.isArray(hole) || hole.length !== 2) throw new Error(`evaluateHoldem requires exactly 2 hole cards, got ${hole?.length ?? 0}`);
  if (!Array.isArray(community) || community.length !== 5) throw new Error(`evaluateHoldem requires exactly 5 community cards, got ${community?.length ?? 0}`);
  const all = [...hole, ...community];
  const seen = new Set();
  for (const card of all) {
    assertHoldemCard(card, 'showdown');
    if (seen.has(card)) throw new Error(`Duplicate card at showdown: ${card}`);
    seen.add(card);
  }
  let best = null;
  let bestRank = -1;
  for (const combo of HOLDEM_FIVE_OF_SEVEN) {
    const evaluated = holdemEvaluateFive(combo.map(i => all[i]));
    const rank = holdemPackRank(HOLDEM_CLASS_RANK[evaluated.handClass], evaluated.tiebreakers);
    if (rank > bestRank) {
      bestRank = rank;
      best = evaluated;
    }
  }
  return holdemHandResult(best);
}

/** 'win' | 'lose' | 'tie' from a's side. Equal rank is an exact tie (split pot); suits never break ties. */
function compareHoldemHands(a, b) {
  if (a.rank > b.rank) return 'win';
  if (a.rank < b.rank) return 'lose';
  return 'tie';
}

/** Showdown of a full deal: both best hands and the result as the fairness record names it. */
function pokerShowdown(deal) {
  const creator = evaluateHoldem(deal.creatorHole, deal.board);
  const opponent = evaluateHoldem(deal.opponentHole, deal.board);
  const cmp = compareHoldemHands(creator, opponent);
  return {
    creator,
    opponent,
    outcome: cmp === 'tie' ? 'split' : 'win',
    winner: cmp === 'win' ? 'creator' : cmp === 'lose' ? 'opponent' : null
  };
}

// ---- Poker recorded result ----
//
// A finished hand's storedOutcome.winningNumber is
//   {"outcome": "win" | "split" | "fold", "contestedAmount": <number>, "community": [cards dealt]}
// and storedOutcome.winner names the seat that took the pot ('creator' |
// 'opponent', null on a split). Hole cards, burns and who folded are not in
// the record. holeCards / handRanks / foldedBy are checked too if a record
// ever carries them (keyed by seat role).

/** Street the hand reached, from how many board cards were dealt. */
function pokerStreetFor(boardCount) {
  return boardCount === 0 ? 'preflop' : boardCount === 3 ? 'flop' : boardCount === 4 ? 'turn' : boardCount === 5 ? 'river' : null;
}

/**
 * Which board mapping the hand was dealt under. The recorded board decides it
 * when it has cards (the two mappings put different deck positions on the
 * board); otherwise the seed reveal time, otherwise the form's setting.
 * `proven` = settled before the burn change existed, so no-burn is certain.
 */
function pokerMappingFor(derived, rec, fallbackBurns) {
  const community = Array.isArray(rec?.deal?.community) ? rec.deal.community : null;
  const revealedMs = Date.parse(rec?.meta?.serverSeedRevealedAt ?? '');
  const settledBeforeBurns = Number.isFinite(revealedMs) ? revealedMs < Date.parse(POKER_BURNS_SINCE) : null;
  if (community && community.length > 0) {
    const fits = (d) => community.length <= 5 && community.every((c, i) => d.board[i] === c);
    if (fits(derived.deals.burn)) return { burnCards: true, by: 'board', settledBeforeBurns };
    if (fits(derived.deals.none)) return { burnCards: false, by: 'board', settledBeforeBurns };
  }
  if (settledBeforeBurns !== null) return { burnCards: !settledBeforeBurns, by: 'date', settledBeforeBurns };
  return { burnCards: fallbackBurns, by: 'form', settledBeforeBurns };
}

/**
 * Compare a derived deal with a recorded Poker hand. Same check shape as
 * Baccarat: { label, status: 'pass' | 'fail' | 'note', expected, recorded, note? }.
 * Returns { checks, mapping, deal, showdown, ended }.
 */
function comparePokerRecord(derived, rec, input, fallbackBurns = true) {
  const checks = [];
  const add = (label, ok, expected, recorded, note) =>
    checks.push({ label, status: ok ? 'pass' : 'fail', expected, recorded, note });
  const fmt = (v) => (Array.isArray(v) ? (v.length ? v.join(' ') : '(none)') : v === null ? 'null' : v === undefined ? '—' : String(v));
  const sameArr = (a, b) => Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => x === b[i]);
  const meta = rec.meta;
  const wn = rec.deal;

  if (meta) compareRecordMeta(meta, input, 'poker', add);

  const mapping = pokerMappingFor(derived, rec, fallbackBurns);
  const deal = mapping.burnCards ? derived.deals.burn : derived.deals.none;
  const result = { checks, mapping, deal, showdown: null, ended: null };
  if (!wn) return result;

  const community = wn.community;
  const boardCount = Array.isArray(community) ? community.length : -1;
  const street = pokerStreetFor(boardCount);
  const outcome = wn.outcome;

  // The board, street by street, as far as it was dealt.
  if (!Array.isArray(community)) {
    add('Board cards', false, fmt(deal.board), fmt(community), 'The record has no board (community) array.');
  } else {
    let mappingNoted = false;
    for (const s of POKER_STREETS) {
      if (s.cards[0] >= boardCount) break;
      const want = s.cards.map(k => deal.board[k]);
      const got = s.cards.map(k => community[k]);
      const idx = s.cards.map(k => deal.boardIndex[k]);
      const label = `Board · ${s.name}`;
      const where = `deck[${idx.join(', ')}]`;
      const ok = sameArr(want, got);
      if (ok && !mapping.burnCards && !mappingNoted) {
        mappingNoted = true;
        if (mapping.settledBeforeBurns === true) {
          add(label, true, `${fmt(want)}  ·  ${where}`, fmt(got),
            'Dealt without burn cards, the mapping every hand used before 2026-10-04; this hand settled before burns existed.');
        } else {
          checks.push({
            label, status: 'note', expected: `${fmt(want)}  ·  ${where}`, recorded: fmt(got),
            note: 'Matches the deal without burn cards used before 2026-10-04. Correct only if the hand was dealt before that change' +
              (mapping.settledBeforeBurns === false ? ' (its seed was revealed after it).' : '; paste the full fairness record to check the date.')
          });
        }
      } else {
        add(label, ok, `${fmt(want)}  ·  ${where}`, fmt(got));
      }
    }
    if (boardCount > 5 || (boardCount > 0 && street === null)) {
      add('Board size', false, '0, 3, 4 or 5 cards', `${boardCount} cards`);
    }
  }

  // How far the hand went, and how it ended.
  const showdownEnd = outcome === 'win' || outcome === 'split';
  if (showdownEnd) {
    result.ended = 'showdown';
    add('Streets dealt', boardCount === 5, 'all five board cards (showdown)', `${Math.max(boardCount, 0)} board card(s)`);
    if (boardCount === 5 || !Array.isArray(community)) {
      const sd = pokerShowdown(deal);
      result.showdown = sd;
      const shown = (o, w) => (o === 'split' ? 'split pot' : `${w ?? '—'} wins`);
      add('Showdown result', outcome === sd.outcome, sd.outcome, fmt(outcome));
      if (rec.winner !== undefined) {
        add('Winning seat', rec.winner === sd.winner, shown(sd.outcome, sd.winner), shown(rec.winner === null ? 'split' : 'win', rec.winner));
      }
    }
  } else if (outcome === 'fold') {
    result.ended = 'fold';
    add('Streets dealt', street !== null, 'board stops at a street: 0, 3, 4 or 5 cards', `${Math.max(boardCount, 0)} board card(s)`);
    if (rec.winner !== undefined) {
      add('Winning seat', rec.winner === 'creator' || rec.winner === 'opponent', 'the seat that did not fold', fmt(rec.winner),
        'Who folds is a player decision, not something the seed decides.');
    }
    if (wn.foldedBy !== undefined && rec.winner !== undefined) {
      add('Folded by', wn.foldedBy !== rec.winner && (wn.foldedBy === 'creator' || wn.foldedBy === 'opponent'),
        rec.winner === 'creator' ? 'opponent' : rec.winner === 'opponent' ? 'creator' : '—', fmt(wn.foldedBy));
    }
  } else {
    add('Outcome', false, 'win, split or fold', fmt(outcome));
  }

  // Fields the current record doesn't carry; checked if a record ever does.
  const holes = wn.holeCards;
  if (holes && typeof holes === 'object') {
    for (const seat of ['creator', 'opponent']) {
      if (holes[seat] === undefined) continue;
      const want = seat === 'creator' ? deal.creatorHole : deal.opponentHole;
      add(`${seat === 'creator' ? 'Creator' : 'Opponent'} hole cards`, sameArr(want, holes[seat]), fmt(want), fmt(holes[seat]));
    }
  }
  const ranks = wn.handRanks;
  if (ranks && typeof ranks === 'object' && result.showdown) {
    for (const seat of ['creator', 'opponent']) {
      const r = ranks[seat];
      if (!r || typeof r !== 'object') continue;
      const want = result.showdown[seat];
      const ok = (r.handClass === undefined || r.handClass === want.handClass)
        && (r.label === undefined || r.label === want.label)
        && (r.rank === undefined || r.rank === want.rank)
        && (r.cards === undefined || sameArr(r.cards, want.cards));
      add(`${seat === 'creator' ? 'Creator' : 'Opponent'} best hand`, ok, `${want.label} · ${want.cards.join(' ')}`,
        `${r.label ?? r.handClass ?? '—'}${Array.isArray(r.cards) ? ` · ${r.cards.join(' ')}` : ''}`);
    }
  }
  return result;
}

async function derivePlinkoBallResults(input, config) {
  const seed = hexToBytes(input.serverSeed);
  const stream = hmacStream(seed, buildMessage(input, 'plinko:balls'));
  const out = [];
  for (let i = 0; i < config.ballCount; i++) {
    out.push(await nextIntInRange(stream, 0, config.slotCount - 1));
  }
  return out;
}

async function derivePlinkoSuddenDeathRolls(input, config) {
  const seed = hexToBytes(input.serverSeed);
  const stream = hmacStream(seed, buildMessage(input, 'plinko:sudden'));
  const out = [];
  for (let i = 0; i < config.maxRounds; i++) {
    out.push(await nextIntInRange(stream, 0, config.slotCount - 1));
  }
  return out;
}

async function derivePlinkoTiebreak(input) {
  const seed = hexToBytes(input.serverSeed);
  const stream = hmacStream(seed, buildMessage(input, 'plinko:tiebreak'));
  return nextIntInRange(stream, 0, 1);
}

// ===========================================================================
// UI DRIVER
// ===========================================================================

const $ = (id) => document.getElementById(id);

function setBanner(kind, text) {
  const banner = $('result-banner');
  banner.className = `banner banner-${kind}`;
  banner.textContent = text;
  $('result-section').classList.remove('hidden');
}

function setDetail(html) {
  $('result-detail').innerHTML = html;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[c]);
}

function readInput() {
  const input = {
    fairnessVersion: FAIRNESS_VERSION,
    gameId: $('gameId').value.trim(),
    serverSeed: $('seed').value.trim().toLowerCase(),
    creatorClientSeed: $('creator').value.trim().toLowerCase(),
    opponentClientSeed: $('opponent').value.trim().toLowerCase()
  };
  const hash = $('hash').value.trim().toLowerCase();
  const gameType = $('gameType').value;
  return { input, hash, gameType, recordText: $('record').value };
}

function validateBeforeDerivation({ input, hash, gameType }) {
  if (!gameType) throw new Error('Pick a game type.');
  if (!input.gameId) throw new Error('Game ID is required.');
  if (!HEX_64_RE.test(hash)) throw new Error('Server Seed Hash must be 64 lowercase hex characters.');
  if (!HEX_64_RE.test(input.serverSeed)) throw new Error('Server Seed must be 64 lowercase hex characters.');
  validateClientSeed(input.creatorClientSeed);
  validateClientSeed(input.opponentClientSeed);
}

async function runDerivation({ input, gameType }) {
  if (gameType === 'number_guess') {
    const cfg = { min: parseInt($('ng_min').value, 10), max: parseInt($('ng_max').value, 10) };
    const target = await deriveNumberGuessTarget(input, cfg);
    return { kind: 'number_guess', cfg, target };
  }
  if (gameType === 'tile_reveal') {
    const rows = parseInt($('tr_rows').value, 10);
    const cols = parseInt($('tr_cols').value, 10);
    const bombs = parseInt($('tr_bombs').value, 10);
    const roundsPlayed = parseInt($('tr_rounds').value, 10) || 1;
    if (roundsPlayed < 1 || roundsPlayed > TILE_REVEAL_MAX_ROUNDS) {
      throw new Error(`Rounds must be between 1 and ${TILE_REVEAL_MAX_ROUNDS}.`);
    }
    const totalTiles = rows * cols;
    const rounds = [];
    for (let r = 1; r <= roundsPlayed; r++) {
      const bombCount = r === 1 ? bombs : bombCountForRound(totalTiles, bombs, r);
      const boards = await deriveTileBoards(input, { totalTiles, bombCount }, r);
      rounds.push({ round: r, bombCount, boards });
    }
    // The flip only decides a game whose final round also tied.
    const tiebreak = roundsPlayed === TILE_REVEAL_MAX_ROUNDS ? await deriveTileRevealTiebreak(input) : null;
    return { kind: 'tile_reveal', cfg: { rows, cols, totalTiles }, rounds, tiebreak };
  }
  if (gameType === 'blackjack') {
    const deck = await deriveShuffledDeck(input);
    return { kind: 'blackjack', deck };
  }
  if (gameType === 'plinko') {
    const slotCount = parseInt($('pk_slots').value, 10);
    const ballCount = parseInt($('pk_balls').value, 10);
    const maxRounds = parseInt($('pk_sudden').value, 10);
    const balls = await derivePlinkoBallResults(input, { slotCount, ballCount });
    const sudden = await derivePlinkoSuddenDeathRolls(input, { slotCount, maxRounds });
    const tiebreak = await derivePlinkoTiebreak(input);
    return { kind: 'plinko', cfg: { slotCount, ballCount, maxRounds }, balls, sudden, tiebreak };
  }
  if (gameType === 'baccarat') {
    const deckCount = parseInt($('bc_decks').value, 10);
    const shoe = await deriveBaccaratShoe(input, deckCount);
    return { kind: 'baccarat', deckCount, shoe, deal: dealPuntoBanco(shoe) };
  }
  if (gameType === 'poker') {
    const deck = await derivePokerDeck(input);
    return {
      kind: 'poker',
      deck,
      deals: { burn: dealPokerHand(deck, true), none: dealPokerHand(deck, false) },
      burnsDefault: $('pkr_burns').value !== 'none'
    };
  }
  throw new Error(`Unsupported game type: ${gameType}`);
}

function renderDerivation(d) {
  if (d.kind === 'number_guess') {
    return `<p>Computed target in [${d.cfg.min}, ${d.cfg.max}]: <strong class="mono">${d.target}</strong></p>`;
  }
  if (d.kind === 'tile_reveal') {
    const multi = d.rounds.length > 1;
    const rounds = d.rounds.map(r => `
      <p>${multi ? `<strong>Round ${r.round}</strong> · ` : ''}${d.cfg.rows}×${d.cfg.cols} grid · ${r.bombCount} bomb(s) per player.</p>
      <div class="board-pair">
        <div><h4>Creator board</h4>${renderBoardGrid(r.boards.creator, d.cfg.rows, d.cfg.cols)}</div>
        <div><h4>Opponent board</h4>${renderBoardGrid(r.boards.opponent, d.cfg.rows, d.cfg.cols)}</div>
      </div>`).join('');
    const flip = d.tiebreak === null ? '' : `
      <p>Coin-flip tiebreak bit (only used if round ${TILE_REVEAL_MAX_ROUNDS} also tied):</p>
      <div class="mono"><strong>${d.tiebreak}</strong> ${d.tiebreak === 0 ? '(creator wins)' : '(opponent wins)'}</div>`;
    return rounds + flip;
  }
  if (d.kind === 'blackjack') {
    return `
      <p>Shuffled 52-card deck (top of deck first):</p>
      <div class="deck-display mono">${d.deck.join(' ')}</div>`;
  }
  if (d.kind === 'plinko') {
    return `
      <p>Ball-result slots (final entry is the gold ball):</p>
      <div class="mono">[${d.balls.join(', ')}]</div>
      <p>Sudden-death rolls (engine walks until tie breaks):</p>
      <div class="mono">[${d.sudden.join(', ')}]</div>
      <p>Coin-flip tiebreak bit (only used if all sudden-death rounds tied):</p>
      <div class="mono"><strong>${d.tiebreak}</strong> ${d.tiebreak === 0 ? '(creator wins)' : '(opponent wins)'}</div>`;
  }
  if (d.kind === 'baccarat') return renderBaccaratDeal(d);
  return '';
}

const SUIT_GLYPHS = { h: '♥', d: '♦', c: '♣', s: '♠' };

function renderCard(card, isThird) {
  const rank = card[0] === 'T' ? '10' : card[0];
  const red = card[1] === 'h' || card[1] === 'd';
  return `<span class="bc-card${red ? ' bc-card-red' : ''}${isThird ? ' bc-card-third' : ''}" title="${escapeHtml(card)}${isThird ? ' · third card' : ''}">`
    + `<span class="bc-card-face">${escapeHtml(rank)}${SUIT_GLYPHS[card[1]] || '?'}</span>`
    + `<span class="bc-card-code">${escapeHtml(card)}${isThird ? ' · 3rd' : ''}</span></span>`;
}

function renderHand(name, hand, score, natural) {
  return `
    <div class="bc-hand">
      <h4>${name}<span class="bc-total">${score}</span>${natural ? '<span class="bc-flag">natural</span>' : ''}</h4>
      <div class="bc-cards">${hand.map((c, i) => renderCard(c, i === 2)).join('')}</div>
    </div>`;
}

/** Plain-language account of which tableau rule fired. */
function baccaratRuleLines(deal) {
  const lines = [];
  if (deal.playerNatural || deal.bankerNatural) {
    const who = deal.playerNatural && deal.bankerNatural ? 'Both hands have'
      : deal.playerNatural ? 'Player has' : 'Banker has';
    lines.push(`${who} a natural (8 or 9 on two cards), so neither side draws.`);
    return lines;
  }
  const playerDrew = deal.playerHand.length === 3;
  const bankerDrew = deal.bankerHand.length === 3;
  lines.push(`Player's two cards total ${deal.playerTwo}: Player ${playerDrew ? 'draws (0–5 draws)' : 'stands (6–7 stand)'}.`);
  if (!playerDrew) {
    lines.push(`Player stood, so Banker plays the same rule: Banker's ${deal.bankerTwo} ${bankerDrew ? 'draws' : 'stands'}.`);
  } else {
    lines.push(`Banker's two cards total ${deal.bankerTwo} and Player's third card is worth ${deal.playerThirdValue}: Banker ${bankerDrew ? 'draws' : 'stands'} (tableau below).`);
  }
  return lines;
}

function renderBaccaratDeal(d) {
  const deal = d.deal;
  const seq = [['P', deal.playerHand[0]], ['B', deal.bankerHand[0]], ['P', deal.playerHand[1]], ['B', deal.bankerHand[1]]];
  if (deal.playerHand[2]) seq.push(['P', deal.playerHand[2]]);
  if (deal.bankerHand[2]) seq.push(['B', deal.bankerHand[2]]);
  const outcomeText = deal.outcome === 'tie'
    ? `Tie · ${deal.playerScore} to ${deal.bankerScore}`
    : `${deal.outcome === 'player' ? 'Player' : 'Banker'} wins · ${Math.max(deal.playerScore, deal.bankerScore)} to ${Math.min(deal.playerScore, deal.bankerScore)}`;
  return `
    <p>Dealt from the top of ${d.deckCount === 8 ? 'an' : 'a'} ${d.deckCount}-deck shoe (${d.shoe.length} cards) in the order Player, Banker, Player, Banker, then any third cards.</p>
    <div class="bc-hands">
      ${renderHand('Player', deal.playerHand, deal.playerScore, deal.playerNatural)}
      ${renderHand('Banker', deal.bankerHand, deal.bankerScore, deal.bankerNatural)}
    </div>
    <div class="bc-outcome bc-outcome-${deal.outcome}">${outcomeText}</div>
    <ol class="bc-rules">${baccaratRuleLines(deal).map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ol>
    <p>Cards in deal order (shoe position · hand · card):</p>
    <div class="deck-display mono">${seq.map(([who, c], i) => `#${i + 1} ${who} ${escapeHtml(c)}`).join(' · ')}</div>
    <details class="bc-shoe">
      <summary>Full shoe, top first (${d.shoe.length} cards)</summary>
      <div class="deck-display mono">${d.shoe.join(' ')}</div>
    </details>`;
}

function renderChecks(checks) {
  const mark = { pass: '✓', fail: '✗', note: '◆' };
  return `<div class="checks">${checks.map(c => {
    const same = c.status === 'pass';
    const values = same
      ? `<code>${escapeHtml(c.expected)}</code>`
      : `<code><span class="check-k">derived</span> ${escapeHtml(c.expected)}</code><code><span class="check-k">recorded</span> ${escapeHtml(c.recorded)}</code>`;
    return `
      <div class="check check-${c.status}">
        <span class="check-mark" aria-label="${c.status}">${mark[c.status]}</span>
        <span class="check-label">${escapeHtml(c.label)}</span>
        <div class="check-values">${values}${c.note ? `<em class="check-note">${escapeHtml(c.note)}</em>` : ''}</div>
      </div>`;
  }).join('')}</div>`;
}

const BACCARAT_SIDE_BET_RULES = `
  <p>Side bets follow from the cards above (gross payout = stake × (multiplier + 1)):</p>
  <ul class="bc-sidebet-rules">
    <li><code>tie</code> totals equal</li>
    <li><code>player_pair</code> / <code>banker_pair</code> that hand's first two cards share a rank</li>
    <li><code>either_pair</code> either hand has a pair · <code>perfect_pair</code> either hand's first two cards are identical (rank and suit)</li>
    <li><code>big</code> 5 or 6 cards dealt · <code>small</code> exactly 4</li>
    <li><code>dragon_7</code> Banker wins with a 3-card 7 · <code>panda_8</code> Player wins with a 3-card 8</li>
    <li><code>dragon_bonus</code> (on a side) natural win 1:1; non-natural win by 9 / 8 / 7 / 6 / 5 / 4 pays 30 / 10 / 6 / 4 / 2 / 1:1; win by 1–3 loses; a tie with a natural pushes</li>
  </ul>`;

const BACCARAT_TABLEAU = `
  <details class="bc-shoe">
    <summary>Banker third-card tableau (when Player drew)</summary>
    <div class="kv"><span>Banker 0–2</span><code>always draws</code></div>
    <div class="kv"><span>Banker 3</span><code>draws unless Player's third card is 8</code></div>
    <div class="kv"><span>Banker 4</span><code>draws on Player third card 2–7</code></div>
    <div class="kv"><span>Banker 5</span><code>draws on Player third card 4–7</code></div>
    <div class="kv"><span>Banker 6</span><code>draws on Player third card 6–7</code></div>
    <div class="kv"><span>Banker 7</span><code>stands</code></div>
  </details>`;

function renderBaccaratResult(parsed, result, rec) {
  const checks = rec ? compareBaccaratRecord(result, rec, parsed.input) : [];
  const failed = checks.filter(c => c.status === 'fail').length;
  const noted = checks.filter(c => c.status === 'note').length;

  if (failed) {
    setBanner('fail', `✗ Mismatch · ${failed} ${failed === 1 ? 'check below disagrees' : 'checks below disagree'} with the cards dealt from the committed shoe.`);
  } else if (rec && !rec.deal) {
    const status = rec.meta?.status ? ` (status: ${rec.meta.status})` : '';
    setBanner('warn', `◆ Hash matches · no deal was recorded for this game${status}. The cards below are what this shoe deals.`);
  } else if (noted) {
    setBanner('warn', '◆ Cards and outcome verified · see the note on the settlement below.');
  } else if (rec) {
    setBanner('ok', '✓ Verified · the recorded deal matches the cards dealt from the committed shoe.');
  } else {
    setBanner('ok', '✓ Hash matches the committed value · deal derived below.');
  }

  const sideBetsRecorded = rec?.deal && ['creatorSideBets', 'opponentSideBets'].some(k => Array.isArray(rec.deal[k]));
  const anySideBets = sideBetsRecorded && ['creatorSideBets', 'opponentSideBets'].some(k => (rec.deal[k] || []).length > 0);
  setDetail(`
    <div class="kv"><span>Hash check</span><code>SHA256(serverSeed) === storedHash ✓</code></div>
    <div class="kv"><span>Algorithm</span><code>v${FAIRNESS_VERSION} · baccarat:shoe</code></div>
    ${checks.length ? `<h4 class="checks-heading">Recorded result vs derivation</h4>${renderChecks(checks)}` : ''}
    ${renderBaccaratDeal(result)}
    ${BACCARAT_TABLEAU}
    ${sideBetsRecorded && !anySideBets ? '<p>No side bets were placed in this game.</p>' : ''}
    ${anySideBets ? '' : BACCARAT_SIDE_BET_RULES}
    ${rec ? '' : '<p class="hint">Paste the game\'s fairness record into <strong>Recorded result</strong> to compare the dealt cards, totals, outcome, settlement and side bets automatically. Otherwise compare the deal above with the game\'s Results screen.</p>'}
    <p class="hint">Main-bet amounts (pot, vig, Banker commission) are not part of the fairness record and are not checked here.</p>
  `);
}

function renderBaccaratUnverifiable(reason, rec) {
  if (reason === 'legacy') {
    setBanner('warn', '◆ This game can\'t be re-derived · it has no provably-fair commitment.');
    setDetail(`
      <p>The record has <code>fairnessVersion: ${escapeHtml(String(rec.meta.fairnessVersion))}</code> or is missing a seed. Games without a full commitment were shuffled by the engine's fallback (a crypto-RNG Fisher-Yates over the same shoe), which leaves nothing to replay. This is not a mismatch; there is simply nothing to check.</p>
    `);
    return;
  }
  setBanner('warn', '◆ The server seed hasn\'t been revealed yet.');
  setDetail('<p>The seed is revealed once the game is completed, cancelled or expired. Come back after the game settles.</p>');
}

// ---- Poker rendering ----

function pokerCardHtml(card, caption, extra = '') {
  const rank = card[0] === 'T' ? '10' : card[0];
  const red = card[1] === 'h' || card[1] === 'd';
  return `<span class="bc-card pk-card${red ? ' bc-card-red' : ''}${extra ? ` ${extra}` : ''}" title="${escapeHtml(card)} · ${escapeHtml(caption)}">`
    + `<span class="bc-card-face">${escapeHtml(rank)}${SUIT_GLYPHS[card[1]] || '?'}</span>`
    + `<span class="bc-card-code">${escapeHtml(card)} · ${escapeHtml(caption)}</span></span>`;
}

/** A card that exists in the deck but was not shown at the table. */
function pokerBackHtml(caption, title) {
  return `<span class="bc-card pk-card pk-card-back" title="${escapeHtml(title)}">`
    + '<span class="pk-back-mark" aria-hidden="true">◆</span>'
    + `<span class="bc-card-code">${escapeHtml(caption)}</span></span>`;
}

/** A board position the hand never reached. */
function pokerSlotHtml(caption) {
  return `<span class="bc-card pk-card pk-card-slot" title="not dealt · ${escapeHtml(caption)}">`
    + '<span class="pk-slot-mark">not dealt</span>'
    + `<span class="bc-card-code">${escapeHtml(caption)}</span></span>`;
}

const POKER_STREET_TITLE = { flop: 'Flop', turn: 'Turn', river: 'River' };

/**
 * The table: each seat's hole cards (and best hand at showdown), then the
 * board street by street with its burn. `view` decides what is face up:
 *   holes   — show both seats' hole cards
 *   burns   — show burn cards face up (else face down, position only)
 *   dealt   — board cards dealt in play (0-5); later ones are "not dealt"
 */
function renderPokerTable(deal, view, showdown) {
  const seat = (name, hole, idx, best) => `
    <div class="bc-hand pk-seat">
      <h4>${name}<span class="pk-pos">deck[${idx.join('] · deck[')}]</span></h4>
      <div class="bc-cards">${view.holes
        ? hole.map((c, i) => pokerCardHtml(c, `[${idx[i]}]`)).join('')
        : idx.map(i => pokerBackHtml(`[${i}]`, `${name} hole card · deck[${i}] · not shown in play`)).join('')}</div>
      ${best ? `<p class="pk-best"><strong>${escapeHtml(best.label)}</strong><span>${escapeHtml(HOLDEM_CLASS_NAME[best.handClass])} · best five: <code>${escapeHtml(best.cards.join(' '))}</code></span></p>` : ''}
      ${view.holes ? '' : '<p class="pk-best"><span>Not shown in play (no showdown).</span></p>'}
    </div>`;
  const streets = POKER_STREETS.map(s => {
    const burn = deal.burns.find(b => b.before === s.name);
    const burnHtml = !burn ? ''
      : view.burns ? pokerCardHtml(burn.card, `burn [${burn.index}]`, 'pk-card-burn')
      : s.cards[0] < view.dealt ? pokerBackHtml(`burn [${burn.index}]`, `burn card · deck[${burn.index}] · never shown`)
      : pokerSlotHtml(`burn [${burn.index}]`);
    const cards = s.cards.map(k => (k < view.dealt
      ? pokerCardHtml(deal.board[k], `[${deal.boardIndex[k]}]`)
      : pokerSlotHtml(`[${deal.boardIndex[k]}]`))).join('');
    return `
      <div class="pk-street">
        <span class="pk-street-name">${POKER_STREET_TITLE[s.name]}</span>
        <div class="pk-street-cards">${burnHtml}${cards}</div>
      </div>`;
  }).join('');
  return `
    <div class="bc-hands pk-seats">
      ${seat('Creator', deal.creatorHole, [0, 2], showdown?.creator)}
      ${seat('Opponent', deal.opponentHole, [1, 3], showdown?.opponent)}
    </div>
    <div class="pk-board">${streets}</div>`;
}

function pokerShowdownText(sd, conditional) {
  const lead = conditional ? 'If the hand reached showdown: ' : '';
  if (sd.outcome === 'split') return `${lead}Split pot · both make ${sd.creator.label}`;
  const w = sd.winner === 'creator' ? sd.creator : sd.opponent;
  const l = sd.winner === 'creator' ? sd.opponent : sd.creator;
  return `${lead}${sd.winner === 'creator' ? 'Creator' : 'Opponent'} wins · ${w.label} beats ${l.label}`;
}

function pokerMappingText(mapping) {
  const how = mapping.burnCards
    ? 'one burn before the flop, the turn and the river (every hand dealt since 2026-10-04)'
    : 'no burn cards (hands dealt before 2026-10-04)';
  const why = mapping.by === 'board' ? 'matched by the recorded board'
    : mapping.by === 'date' ? 'chosen from when the seed was revealed'
    : 'the form setting';
  return `${how} · ${why}`;
}

function pokerDeckHtml(deck) {
  return `<div class="deck-display mono">${deck.map((c, i) => `${i}:${escapeHtml(c)}`).join(' ')}</div>`;
}

function renderPokerResult(parsed, result, rec) {
  const cmp = rec ? comparePokerRecord(result, rec, parsed.input, result.burnsDefault) : null;
  const checks = cmp ? cmp.checks : [];
  const failed = checks.filter(c => c.status === 'fail').length;
  const noted = checks.filter(c => c.status === 'note').length;
  const mapping = cmp ? cmp.mapping : { burnCards: result.burnsDefault, by: 'form' };
  const deal = mapping.burnCards ? result.deals.burn : result.deals.none;
  const ended = cmp ? cmp.ended : null;
  const wn = rec?.deal || null;

  if (failed) {
    setBanner('fail', `✗ Mismatch · ${failed} ${failed === 1 ? 'check below disagrees' : 'checks below disagree'} with the cards dealt from the committed deck.`);
  } else if (rec && !wn) {
    const status = rec.meta?.status ? ` (status: ${rec.meta.status})` : '';
    setBanner('warn', `◆ Hash matches · no hand was recorded for this game${status}. The cards below are what this deck deals.`);
  } else if (noted) {
    setBanner('warn', '◆ Board verified · see the note on the deal mapping below.');
  } else if (ended === 'fold') {
    setBanner('ok', '✓ Verified · the recorded board matches the committed deck. The hand ended by a fold.');
  } else if (ended === 'showdown') {
    setBanner('ok', '✓ Verified · the recorded board and showdown result match the cards dealt from the committed deck.');
  } else {
    setBanner('ok', '✓ Hash matches the committed value · deal derived below.');
  }

  // What is face up. Seeds only: everything (the deal is the only thing to
  // check). With a record: only what was shown in play; the rest goes behind
  // the disclosure below.
  let table;
  let unrevealed = '';
  const fullDeck = `<p>Full deck, top first (0-based positions):</p>${pokerDeckHtml(result.deck)}`;
  if (!rec || !wn) {
    const sd = pokerShowdown(deal);
    table = `
      <p>Dealt from the top of the deck: creator, opponent, creator, opponent; then ${deal.burnCards ? 'burn, flop, burn, turn, burn, river' : 'the flop, turn and river with no burns'}. Positions are 0-based deck indices.</p>
      ${renderPokerTable(deal, { holes: true, burns: true, dealt: 5 }, sd)}
      <div class="bc-outcome">${escapeHtml(pokerShowdownText(sd, true))}</div>
      <p class="hint">A hand that ended by a fold stopped earlier: only the board up to that street was dealt and neither hand was shown. This view shows every position because, with seeds only, the deal is what there is to check.</p>
      <details class="bc-shoe"><summary>Full deck, top first (52 cards)</summary>${pokerDeckHtml(result.deck)}</details>`;
  } else if (ended === 'fold') {
    const dealt = Array.isArray(wn.community) ? Math.min(wn.community.length, 5) : 0;
    const street = pokerStreetFor(dealt) || 'an unknown street';
    const folder = rec.winner === 'creator' ? 'Opponent' : rec.winner === 'opponent' ? 'Creator' : null;
    const who = folder ? `${folder} folded ${street === 'preflop' ? 'preflop' : `on the ${street}`} · ${folder === 'Creator' ? 'opponent' : 'creator'} takes the pot`
      : `Hand ended by a fold ${street === 'preflop' ? 'preflop' : `on the ${street}`}`;
    table = `
      <p>The hand ended by a fold, so there was no showdown: neither player's hole cards were shown, and ${dealt === 5 ? 'the whole board was dealt' : dealt === 0 ? 'no board card was dealt' : `the board stopped at the ${street}`}. Only what was dealt in play is shown here.</p>
      ${renderPokerTable(deal, { holes: false, burns: false, dealt }, null)}
      <div class="bc-outcome">${escapeHtml(who)}</div>
      <p class="hint">The remaining deck order — both hands, the burn cards and the board that was never dealt — is fixed by the committed seed, so it could not have been changed after the hash was published. Those cards were never shown at the table and are kept closed below.</p>`;
    const undealt = [0, 1, 2, 3, 4].filter(k => k >= dealt);
    unrevealed = `
      <details class="bc-shoe pk-unrevealed">
        <summary>Show cards that were not revealed in play</summary>
        <p>Computed from the revealed seed. None of these were shown to either player during the hand.</p>
        ${renderPokerTable(deal, { holes: true, burns: true, dealt: 5 }, null)}
        <div class="kv"><span>Board never dealt</span><code class="pk-kv-text">${undealt.length ? undealt.map(k => `${deal.board[k]} [${deal.boardIndex[k]}]`).join(' · ') : 'none (the river was dealt)'}</code></div>
        ${fullDeck}
      </details>`;
  } else {
    const sd = cmp.showdown || pokerShowdown(deal);
    table = `
      <p>Dealt from the top of the deck: creator, opponent, creator, opponent; then ${deal.burnCards ? 'burn, flop, burn, turn, burn, river' : 'the flop, turn and river with no burns'}. Positions are 0-based deck indices. Burn cards are never shown at the table.</p>
      ${renderPokerTable(deal, { holes: true, burns: false, dealt: 5 }, sd)}
      <div class="bc-outcome">${escapeHtml(pokerShowdownText(sd, false))}</div>`;
    unrevealed = `
      <details class="bc-shoe pk-unrevealed">
        <summary>Show cards that were not revealed in play</summary>
        <p>Computed from the revealed seed: the burn cards and the rest of the deck.</p>
        <div class="kv"><span>Burn cards</span><code class="pk-kv-text">${deal.burns.length ? deal.burns.map(b => `${b.card} [${b.index}] before the ${b.before}`).join(' · ') : 'none (dealt before burns existed)'}</code></div>
        ${fullDeck}
      </details>`;
  }

  const contested = wn && wn.contestedAmount !== undefined
    ? `<div class="kv"><span>Contested amount</span><code class="pk-kv-text">${escapeHtml(String(wn.contestedAmount))} per player · recorded, not checked</code></div>` : '';
  setDetail(`
    <div class="kv"><span>Hash check</span><code>SHA256(serverSeed) === storedHash ✓</code></div>
    <div class="kv"><span>Algorithm</span><code>v${FAIRNESS_VERSION} · poker:deck</code></div>
    <div class="kv"><span>Board mapping</span><code class="pk-kv-text">${escapeHtml(pokerMappingText(mapping))}</code></div>
    ${contested}
    ${checks.length ? `<h4 class="checks-heading">Recorded result vs derivation</h4>${renderChecks(checks)}` : ''}
    ${table}
    ${unrevealed}
    ${rec ? '' : '<p class="hint">Paste the game\'s fairness record into <strong>Recorded result</strong> to compare the board, the showdown result and the winning seat automatically. Otherwise compare the deal above with the game\'s Results screen.</p>'}
    ${rec && !rec.meta && wn ? '<p class="hint">Only a winningNumber was pasted, so the winning seat is not checked; paste the full fairness record for that.</p>' : ''}
    <p class="hint">Betting (amounts, pot, uncalled bets returned, rake) is decided by the players and the settlement, not by the seed, and is not checked here.</p>
  `);
}

function renderPokerUnverifiable(reason, rec) {
  if (reason === 'legacy') {
    setBanner('warn', '◆ This game can\'t be re-derived · it has no provably-fair commitment.');
    setDetail(`
      <p>The record has <code>fairnessVersion: ${escapeHtml(String(rec.meta.fairnessVersion))}</code> or is missing a seed. Without a full commitment the engine shuffles with its fallback (a crypto-RNG Fisher-Yates over the same 52-card deck), which leaves nothing to replay. This is not a mismatch; there is simply nothing to check.</p>
    `);
    return;
  }
  renderBaccaratUnverifiable(reason, rec);
}

function renderBoardGrid(board, rows, cols) {
  let s = `<div class="board" style="grid-template-columns: repeat(${cols}, 1fr)">`;
  for (let i = 0; i < rows * cols; i++) {
    s += `<div class="cell ${board[i] === 1 ? 'cell-bomb' : 'cell-safe'}">${board[i] === 1 ? '💣' : ''}</div>`;
  }
  s += '</div>';
  return s;
}

async function handleVerify(e) {
  e.preventDefault();
  const btn = $('verify-btn');
  btn.disabled = true;
  btn.textContent = 'Verifying…';
  try {
    const parsed = readInput();

    // Baccarat can be checked against the game's recorded result. A record
    // with no provably-fair commitment can't be replayed at all — say so
    // before field validation complains about the missing seeds.
    let record = null;
    if ((parsed.gameType === 'baccarat' || parsed.gameType === 'poker') && parsed.recordText.trim()) {
      record = parseRecordedResult(parsed.recordText);
      if (parsed.gameType === 'poker' && record.deal && !Array.isArray(record.deal.community) && record.deal.playerHand !== undefined) {
        throw new Error('The recorded result is a Baccarat deal, not a Poker hand.');
      }
      const reason = baccaratRecordUnverifiableReason(record);
      if (reason) {
        if (parsed.gameType === 'poker') renderPokerUnverifiable(reason, record);
        else renderBaccaratUnverifiable(reason, record);
        return;
      }
    }

    validateBeforeDerivation(parsed);

    // Step 1: hash check.
    const computedHash = await sha256Hex(hexToBytes(parsed.input.serverSeed));
    if (computedHash !== parsed.hash) {
      setBanner(
        'fail',
        '✗ Hash mismatch — the revealed server seed does not match the committed hash.'
      );
      setDetail(`
        <div class="kv"><span>Computed</span><code>${escapeHtml(computedHash)}</code></div>
        <div class="kv"><span>Stored</span><code>${escapeHtml(parsed.hash)}</code></div>
        <p class="hint">This is a critical bug — please report with the Game ID.</p>
      `);
      return;
    }

    // Step 2: derive outcome.
    const result = await runDerivation(parsed);
    if (result.kind === 'baccarat') {
      renderBaccaratResult(parsed, result, record);
      return;
    }
    if (result.kind === 'poker') {
      renderPokerResult(parsed, result, record);
      return;
    }
    setBanner('ok', '✓ Hash matches the committed value · outcome derived below.');
    setDetail(`
      <div class="kv"><span>Hash check</span><code>SHA256(serverSeed) === storedHash ✓</code></div>
      <div class="kv"><span>Algorithm</span><code>v${FAIRNESS_VERSION}</code></div>
      ${renderDerivation(result)}
      <p class="hint">Compare the derivation above to what FiftyFifty stored for this game. They should match exactly. If they don't, please report with the Game ID.</p>
      ${parsed.recordText.trim() ? '<p class="hint">The automatic recorded-result comparison covers Baccarat and Poker so far; compare this game by hand.</p>' : ''}
    `);
  } catch (err) {
    setBanner('fail', '✗ Could not verify');
    setDetail(`<p class="error">${escapeHtml(err.message || String(err))}</p>`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Verify';
  }
}

/**
 * A pasted fairness record (the /fairness JSON) carries everything the form
 * needs; copy it in so the user doesn't have to. A bare winningNumber has no
 * seeds and fills nothing.
 */
function applyRecordToForm() {
  let rec;
  try {
    rec = parseRecordedResult($('record').value);
  } catch {
    return;
  }
  const m = rec?.meta;
  if (!m) return;
  const set = (id, v) => {
    if (typeof v === 'string' && v !== '') $(id).value = v;
  };
  set('gameId', m.gameId);
  set('hash', m.serverSeedHash);
  set('seed', m.serverSeed);
  set('creator', m.creatorClientSeed);
  set('opponent', m.opponentClientSeed);
  if (m.gameType && [...$('gameType').options].some(o => o.value === m.gameType)) {
    $('gameType').value = m.gameType;
  }
  if (m.gameType === 'baccarat' && Number.isInteger(m.gameConfig?.deck_count)) {
    $('bc_decks').value = String(m.gameConfig.deck_count);
  }
}

function applyUrlPrefill() {
  const params = new URLSearchParams(window.location.search);
  const setIf = (id, key) => {
    const v = params.get(key);
    if (v != null) $(id).value = v;
  };
  // The record first, so explicit URL fields below take precedence.
  setIf('record', 'record');
  applyRecordToForm();
  setIf('bc_decks', 'decks');
  setIf('pkr_burns', 'burns');
  setIf('gameId', 'gameId');
  setIf('hash', 'hash');
  setIf('seed', 'seed');
  setIf('creator', 'creator');
  setIf('opponent', 'opponent');
  setIf('tr_bombs', 'bombs');
  setIf('tr_rounds', 'rounds');
  const type = params.get('type');
  if (type) $('gameType').value = type;
}

function handleClear() {
  $('verify-form').reset();
  $('result-section').classList.add('hidden');
  setDetail('');
}

document.addEventListener('DOMContentLoaded', () => {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    setBanner('fail', 'Your browser does not expose Web Crypto. Try a modern Chrome/Firefox/Safari.');
    return;
  }
  applyUrlPrefill();
  $('verify-form').addEventListener('submit', handleVerify);
  $('clear-btn').addEventListener('click', handleClear);
  $('record').addEventListener('input', applyRecordToForm);
});
