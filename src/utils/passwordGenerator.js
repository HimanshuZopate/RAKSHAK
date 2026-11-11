/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * CRYPTOGRAPHICALLY SECURE PASSWORD & PASSPHRASE GENERATOR
 * ═══════════════════════════════════════════════════════════════════════════════
 * Uses the Web Crypto API (window.crypto.getRandomValues) with rejection
 * sampling to ensure zero modulo bias and genuine cryptographic entropy.
 * Never logs, sends, or stores generated secrets.
 */

// Character set pools
const CHARSET_UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const CHARSET_LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const CHARSET_NUMBERS = '0123456789';
const CHARSET_SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?';

// Ambiguous characters: O, 0, l, 1, I, |
const AMBIGUOUS_SET = new Set(['O', '0', 'l', '1', 'I', '|', '`', '\'', '"', ';', ':']);

/**
 * Filter out ambiguous characters from a charset string
 */
const removeAmbiguousChars = (charset) => {
  return charset
    .split('')
    .filter((ch) => !AMBIGUOUS_SET.has(ch))
    .join('');
};

/**
 * Unbiased random integer selection in range [0, max - 1] using rejection sampling.
 * Eliminates modulo bias completely.
 * @param {number} max - Upper bound (exclusive)
 * @returns {number} Unbiased random integer
 */
const getSecureRandomInt = (max) => {
  if (max <= 1) return 0;
  // Calculate highest multiple of max below 2^32
  const limit = Math.floor(0x100000000 / max) * max;
  const buffer = new Uint32Array(1);

  while (true) {
    window.crypto.getRandomValues(buffer);
    const rand = buffer[0];
    if (rand < limit) {
      return rand % max;
    }
  }
};

/**
 * Cryptographically secure Fisher-Yates shuffle
 */
const secureShuffle = (array) => {
  const result = [...array];
  for (let i = result.length - 1; i > 0; i--) {
    const j = getSecureRandomInt(i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
};

/**
 * Generate a Cryptographically Secure Random Password
 * @param {object} options - Generator settings
 * @returns {string} Generated password
 */
export const generateSecurePassword = ({
  length = 16,
  includeUppercase = true,
  includeLowercase = true,
  includeNumbers = true,
  includeSymbols = true,
  excludeAmbiguous = false,
} = {}) => {
  const safeLength = Math.max(8, Math.min(64, Number(length) || 16));

  let upperPool = includeUppercase ? CHARSET_UPPERCASE : '';
  let lowerPool = includeLowercase ? CHARSET_LOWERCASE : '';
  let numberPool = includeNumbers ? CHARSET_NUMBERS : '';
  let symbolPool = includeSymbols ? CHARSET_SYMBOLS : '';

  if (excludeAmbiguous) {
    upperPool = removeAmbiguousChars(upperPool);
    lowerPool = removeAmbiguousChars(lowerPool);
    numberPool = removeAmbiguousChars(numberPool);
    symbolPool = removeAmbiguousChars(symbolPool);
  }

  const enabledPools = [];
  if (upperPool) enabledPools.push(upperPool);
  if (lowerPool) enabledPools.push(lowerPool);
  if (numberPool) enabledPools.push(numberPool);
  if (symbolPool) enabledPools.push(symbolPool);

  // Fallback: If all categories are deselected, default to lowercase + uppercase + numbers
  if (enabledPools.length === 0) {
    return generateSecurePassword({
      length: safeLength,
      includeUppercase: true,
      includeLowercase: true,
      includeNumbers: true,
      includeSymbols: false,
      excludeAmbiguous,
    });
  }

  const combinedCharset = enabledPools.join('');
  const passwordChars = [];

  // Guarantee at least one character from each enabled pool
  for (const pool of enabledPools) {
    const charIndex = getSecureRandomInt(pool.length);
    passwordChars.push(pool[charIndex]);
  }

  // Fill remaining length from full combined charset
  const remainingCount = safeLength - passwordChars.length;
  for (let i = 0; i < remainingCount; i++) {
    const charIndex = getSecureRandomInt(combinedCharset.length);
    passwordChars.push(combinedCharset[charIndex]);
  }

  // Cryptographically shuffle to prevent predictable initial category order
  const shuffled = secureShuffle(passwordChars);
  return shuffled.join('');
};

/**
 * Curated EFF-inspired Diceware Wordlist for Memorable Passphrases (350+ words)
 */
export const PASSPHRASE_WORDLIST = [
  'amber', 'anchor', 'apex', 'archer', 'arctic', 'atlas', 'aurora', 'avatar',
  'badger', 'beacon', 'bison', 'blade', 'boulder', 'breeze', 'bronze', 'canyon',
  'cascade', 'cedar', 'cipher', 'citadel', 'cliff', 'clover', 'cobalt', 'comet',
  'compass', 'copper', 'coral', 'cosmos', 'crater', 'crystal', 'curator', 'dagger',
  'delta', 'desert', 'diamond', 'dolphin', 'dragon', 'drift', 'eagle', 'echo',
  'eclipse', 'ember', 'emerald', 'enigma', 'falcon', 'fathom', 'fern', 'flare',
  'flint', 'forest', 'forge', 'fossil', 'frost', 'galaxy', 'garnet', 'glacier',
  'glade', 'granite', 'harbor', 'hawk', 'haven', 'helix', 'horizon', 'hunter',
  'hydra', 'impact', 'indigo', 'iron', 'island', 'jaguar', 'javelin', 'juniper',
  'kestrel', 'knight', 'lagoon', 'lantern', 'laser', 'legacy', 'legend', 'leopard',
  'lightning', 'lotus', 'lunar', 'lynx', 'magnet', 'mantle', 'marble', 'matrix',
  'meadow', 'meteor', 'mirage', 'monarch', 'monolith', 'moon', 'moss', 'mountain',
  'mystic', 'nebula', 'nexus', 'night', 'ninja', 'noble', 'nomad', 'north',
  'nova', 'oasis', 'obsidian', 'ocean', 'onyx', 'oracle', 'orbit', 'orchid',
  'osprey', 'outpost', 'panther', 'passage', 'pathway', 'pelican', 'phantom',
  'phoenix', 'pinnacle', 'pioneer', 'planet', 'plasma', 'polar', 'portal',
  'prism', 'pulsar', 'pulse', 'pyramid', 'quantum', 'quarry', 'quartz', 'quasar',
  'radiant', 'raptor', 'raven', 'reef', 'relic', 'resistor', 'ridge', 'rift',
  'ripple', 'river', 'rocket', 'rover', 'ruby', 'sable', 'saffron', 'sapphire',
  'saturn', 'sentry', 'seraph', 'shadow', 'shield', 'sierra', 'silver', 'solstice',
  'sonar', 'spark', 'spectrum', 'sphinx', 'spider', 'spiral', 'summit', 'sunburst',
  'sunset', 'surge', 'swift', 'tempest', 'thermal', 'thunder', 'timber', 'titan',
  'topaz', 'torrent', 'tracker', 'trail', 'trident', 'tundra', 'twilight', 'typhoon',
  'valiant', 'valley', 'vanguard', 'vector', 'velocity', 'vertex', 'viper', 'vortex',
  'voyage', 'vulcan', 'warden', 'warrior', 'wave', 'willow', 'wind', 'wolf',
  'zenith', 'zephyr', 'zero', 'zodiac', 'acorn', 'albatross', 'almond', 'alpaca',
  'alpine', 'amazon', 'amethyst', 'arrow', 'asteroid', 'avalanche', 'aztec',
  'bamboo', 'basalt', 'battleship', 'blizzard', 'bonsai', 'boundless', 'bravery',
  'brigade', 'brilliant', 'calico', 'camel', 'canvas', 'cardinal', 'castaway',
  'catalyst', 'cavalier', 'celestial', 'chameleon', 'champion', 'cheetah', 'chimera',
  'cinnamon', 'cloud', 'conquest', 'constellation', 'copperhead', 'cormorant',
  'coyote', 'crane', 'crimson', 'crusader', 'cyclone', 'dandelion', 'dawn',
  'defender', 'discovery', 'dynasty', 'dynamo', 'element', 'elephant', 'elixir',
  'explorer', 'express', 'feather', 'ferocious', 'firefly', 'firewall', 'flamingo',
  'fortress', 'frontier', 'galaxy', 'gateway', 'geyser', 'glimmer', 'grizzly',
  'guardian', 'halogen', 'harmony', 'harpoon', 'hazard', 'headline', 'herald',
  'highland', 'horizon', 'hurricane', 'iceberg', 'illustrious', 'infinite', 'intrepid',
  'islander', 'jackal', 'jasmine', 'javelin', 'journey', 'jupiter', 'kaleidoscope',
  'kingfisher', 'labyrinth', 'landmark', 'liberty', 'lighthouse', 'lucid', 'luminary',
  'magma', 'majestic', 'mammoth', 'mariner', 'maverick', 'meridian', 'midnight',
  'militia', 'mineral', 'molecule', 'navigator', 'nemesis', 'neon', 'nocturnal',
  'nomadic', 'nugget', 'olympic', 'opal', 'orbit', 'origami', 'overland',
  'paladin', 'panorama', 'paragon', 'patriot', 'pendulum', 'permafrost', 'petrel',
  'pilot', 'platinum', 'plover', 'polaris', 'predator', 'premier', 'proton',
  'prowler', 'radiance', 'ranger', 'rebellion', 'redwood', 'resonance', 'rhino',
  'roamer', 'runestone', 'safari', 'sagittarius', 'salute', 'satellite', 'scorpion',
  'sentinel', 'sequoia', 'shadowfax', 'shaman', 'stalwart', 'stealth', 'stellar',
  'stranger', 'stride', 'stronghold', 'sunflower', 'supernova', 'survival', 'tactician',
  'talisman', 'terraform', 'thermostat', 'threshold', 'timeless', 'titanium',
  'tornado', 'trailblazer', 'tribune', 'tsunami', 'turbine', 'vampire', 'vessel',
  'vigilant', 'voyager', 'wanderer', 'watchtower', 'whisper', 'wildcat', 'wizard'
];

/**
 * Generate a Cryptographically Secure Passphrase
 * @param {object} options - Passphrase generation settings
 * @returns {string} Memorable passphrase
 */
export const generateSecurePassphrase = ({
  wordCount = 4,
  separator = '-',
  capitalize = 'title', // 'title', 'lower', 'upper'
  includeSuffix = true,
  suffixType = 'number', // 'number', 'symbol', 'both'
} = {}) => {
  const safeCount = Math.max(3, Math.min(8, Number(wordCount) || 4));
  const selectedWords = [];

  for (let i = 0; i < safeCount; i++) {
    const idx = getSecureRandomInt(PASSPHRASE_WORDLIST.length);
    let word = PASSPHRASE_WORDLIST[idx];

    if (capitalize === 'title') {
      word = word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
    } else if (capitalize === 'upper') {
      word = word.toUpperCase();
    } else {
      word = word.toLowerCase();
    }

    selectedWords.push(word);
  }

  let result = selectedWords.join(separator);

  if (includeSuffix) {
    if (suffixType === 'number' || suffixType === 'both') {
      const num = getSecureRandomInt(900) + 100; // 3-digit number (100-999)
      result += `${separator}${num}`;
    }
    if (suffixType === 'symbol' || suffixType === 'both') {
      const symbols = '!@#$%^&*';
      const sym = symbols[getSecureRandomInt(symbols.length)];
      result += sym;
    }
  }

  return result;
};
