/**
 * FiftyFifty Provably-Fair Verifier — standalone, no framework.
 *
 * This file contains:
 *   1. A copy of the canonical fairness algorithm (locked at FAIRNESS_VERSION = 1).
 *      It is intentionally identical to fifty-frontend/src/utils/fairness.js
 *      and to the backend's fairness.ts. The shared test-vectors/fairness-vectors.json
 *      file is the spec — three implementations, one truth.
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

async function deriveTileBoards(input, config) {
  const seed = hexToBytes(input.serverSeed);
  return {
    creator: await deriveBombBoard(seed, buildMessage(input, 'tile-reveal:board:creator'), config),
    opponent: await deriveBombBoard(seed, buildMessage(input, 'tile-reveal:board:opponent'), config)
  };
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
  return { input, hash, gameType };
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
    const cfg = { totalTiles: rows * cols, bombCount: bombs };
    const boards = await deriveTileBoards(input, cfg);
    return { kind: 'tile_reveal', cfg: { rows, cols, ...cfg }, boards };
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
  throw new Error(`Unsupported game type: ${gameType}`);
}

function renderDerivation(d) {
  if (d.kind === 'number_guess') {
    return `<p>Computed target in [${d.cfg.min}, ${d.cfg.max}]: <strong class="mono">${d.target}</strong></p>`;
  }
  if (d.kind === 'tile_reveal') {
    return `
      <p>${d.cfg.rows}×${d.cfg.cols} grid · ${d.cfg.bombCount} bomb(s) per player.</p>
      <div class="board-pair">
        <div><h4>Creator board</h4>${renderBoardGrid(d.boards.creator, d.cfg.rows, d.cfg.cols)}</div>
        <div><h4>Opponent board</h4>${renderBoardGrid(d.boards.opponent, d.cfg.rows, d.cfg.cols)}</div>
      </div>`;
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
  return '';
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
    setBanner('ok', '✓ Hash matches the committed value · outcome derived below.');
    setDetail(`
      <div class="kv"><span>Hash check</span><code>SHA256(serverSeed) === storedHash ✓</code></div>
      <div class="kv"><span>Algorithm</span><code>v${FAIRNESS_VERSION}</code></div>
      ${renderDerivation(result)}
      <p class="hint">Compare the derivation above to what FiftyFifty stored for this game. They should match exactly. If they don't, please report with the Game ID.</p>
    `);
  } catch (err) {
    setBanner('fail', '✗ Could not verify');
    setDetail(`<p class="error">${escapeHtml(err.message || String(err))}</p>`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Verify';
  }
}

function applyUrlPrefill() {
  const params = new URLSearchParams(window.location.search);
  const setIf = (id, key) => {
    const v = params.get(key);
    if (v != null) $(id).value = v;
  };
  setIf('gameId', 'gameId');
  setIf('hash', 'hash');
  setIf('seed', 'seed');
  setIf('creator', 'creator');
  setIf('opponent', 'opponent');
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
});
