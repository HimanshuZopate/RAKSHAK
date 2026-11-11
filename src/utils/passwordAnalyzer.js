/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * PASSWORD SECURITY ANALYZER (100% CLIENT-SIDE)
 * ═══════════════════════════════════════════════════════════════════════════════
 * Privacy Notice: This module executes strictly in the user's browser.
 * No password data is ever transmitted, logged, or stored.
 */

// Common notorious passwords and predictable words (lowercase)
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', '123456', '12345678', '123456789',
  '12345', 'qwerty', 'admin', 'welcome', 'login', 'letmein', 'iloveyou',
  'sunshine', 'monkey', 'dragon', 'football', 'master', 'superman', 'trustno1',
  'starwars', 'killer', 'hunter', 'shadow', 'security', 'computer', 'access',
  'secret', 'pass123', 'testing', 'hello', 'chelsea', 'arsenal', 'liverpool',
  'barcelona', 'default', 'root', 'administrator', 'changeit', 'system',
  'passcode', 'p@ssword', 'p@ssw0rd', 'guest', 'company', 'charlie', 'robert',
  'thomas', 'hockey', 'baseball', 'princess', 'solo', 'michael', 'jessica'
]);

// Keyboard sequence patterns (QWERTY layout)
const KEYBOARD_ROWS = [
  '1234567890-=',
  'qwertyuiop[]\\',
  'asdfghjkl;\'',
  'zxcvbnm,./'
];

/**
 * Standard Leet-speak character substitutions mapping
 */
const LEET_MAP = {
  '@': 'a', '4': 'a',
  '8': 'b',
  '(': 'c', '<': 'c',
  '3': 'e',
  '6': 'g', '9': 'g',
  '!': 'i', '1': 'i', '|': 'i',
  '0': 'o',
  '5': 's', '$': 's',
  '7': 't', '+': 't',
  '2': 'z', '%': 'x'
};

/**
 * Convert leet-speak representation back to standard letters
 */
const decodeLeet = (str) => {
  let decoded = '';
  for (const ch of str.toLowerCase()) {
    decoded += LEET_MAP[ch] || ch;
  }
  return decoded;
};

/**
 * Check if the password contains sequential alphabet characters (e.g., "abc", "xyz", "cba")
 */
const findSequentialAlphabet = (str) => {
  const lower = str.toLowerCase();
  for (let i = 0; i < lower.length - 2; i++) {
    const c1 = lower.charCodeAt(i);
    const c2 = lower.charCodeAt(i + 1);
    const c3 = lower.charCodeAt(i + 2);
    // Only check alphabetical ASCII (97-122)
    if (c1 >= 97 && c1 <= 122 && c2 >= 97 && c2 <= 122 && c3 >= 97 && c3 <= 122) {
      if ((c2 === c1 + 1 && c3 === c2 + 1) || (c2 === c1 - 1 && c3 === c2 - 1)) {
        return true;
      }
    }
  }
  return false;
};

/**
 * Check if the password contains sequential numeric characters (e.g., "1234", "9876")
 */
const findSequentialNumbers = (str) => {
  for (let i = 0; i < str.length - 2; i++) {
    const c1 = str.charCodeAt(i);
    const c2 = str.charCodeAt(i + 1);
    const c3 = str.charCodeAt(i + 2);
    // Digits ASCII (48-57)
    if (c1 >= 48 && c1 <= 57 && c2 >= 48 && c2 <= 57 && c3 >= 48 && c3 <= 57) {
      if ((c2 === c1 + 1 && c3 === c2 + 1) || (c2 === c1 - 1 && c3 === c2 - 1)) {
        return true;
      }
    }
  }
  return false;
};

/**
 * Check for consecutive QWERTY keyboard sequences (e.g., "qwe", "asdf")
 */
const findKeyboardSequence = (str) => {
  const lower = str.toLowerCase();
  for (const row of KEYBOARD_ROWS) {
    for (let i = 0; i < row.length - 2; i++) {
      const forward = row.substring(i, i + 3);
      const reverse = forward.split('').reverse().join('');
      if (lower.includes(forward) || lower.includes(reverse)) {
        return true;
      }
    }
  }
  return false;
};

/**
 * Detect consecutive identical repeated characters (e.g., "aaa", "111")
 */
const findRepeatedChars = (str) => {
  for (let i = 0; i < str.length - 2; i++) {
    if (str[i] === str[i + 1] && str[i] === str[i + 2]) {
      return true;
    }
  }
  return false;
};

/**
 * Detect four-digit year patterns (1950 - 2035)
 */
const findYearPattern = (str) => {
  const yearMatch = str.match(/(19\d\d|20[0-3]\d)/);
  return Boolean(yearMatch);
};

/**
 * Check if the password has structure of a passphrase:
 * At least 3 words separated by spaces, hyphens, periods, or underscores, and length >= 14
 */
const isPassphraseCandidate = (str) => {
  if (str.length < 14) return false;
  const parts = str.trim().split(/[\s\-_.]+/);
  return parts.length >= 3 && parts.every((p) => p.length >= 2);
};

/**
 * Calculate Shannon Entropy in bits
 */
const calculateShannonEntropy = (str) => {
  if (!str) return 0;
  const freq = {};
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  // Total bits of entropy = average entropy per character * length
  return Math.round(entropy * len * 10) / 10;
};

/**
 * Format large guess counts into human-readable crack time estimates
 */
const formatCrackTime = (seconds) => {
  if (seconds < 0.001) return 'Instant (< 1 ms)';
  if (seconds < 1) return 'Less than a second';
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${Math.round(minutes)} minutes`;
  const hours = minutes / 60;
  if (hours < 24) return `${Math.round(hours)} hours`;
  const days = hours / 24;
  if (days < 30) return `${Math.round(days)} days`;
  const months = days / 30.4;
  if (months < 12) return `${Math.round(months)} months`;
  const years = days / 365.25;
  if (years < 100) return `${Math.round(years)} years`;
  if (years < 10000) return `${Math.round(years).toLocaleString()} years`;
  if (years < 1e6) return `${(years / 1000).toFixed(1)} thousand years`;
  if (years < 1e9) return `${(years / 1e6).toFixed(1)} million years`;
  if (years < 1e12) return `${(years / 1e9).toFixed(1)} billion years`;
  return 'Trillions of years (Unfeasible)';
};

/**
 * Core Password Analyzer Function
 * @param {string} password - Raw password entered by user
 * @returns {object} Detailed analysis results and metrics
 */
export const analyzePassword = (password) => {
  if (!password || typeof password !== 'string') {
    return {
      isEmpty: true,
      score: 0,
      scorePercent: 0,
      label: 'Enter a password to begin',
      color: 'slate',
      themeKey: 'empty',
      length: 0,
      charSets: { lowercase: 0, uppercase: 0, numbers: 0, symbols: 0 },
      poolSize: 0,
      entropyBits: 0,
      shannonBits: 0,
      isPassphrase: false,
      crackTimes: {
        online: 'N/A',
        slowHash: 'N/A',
        fastGpu: 'N/A',
      },
      indicators: [],
      suggestions: [
        'Enter a password or generate one using the tool below.',
        'Use at least 14-16 characters for resilient security.',
        'Consider using a memorable passphrase of 4+ unrelated words.',
      ],
      warnings: [],
      strengths: [],
    };
  }

  const length = password.length;
  const lowerCount = (password.match(/[a-z]/g) || []).length;
  const upperCount = (password.match(/[A-Z]/g) || []).length;
  const numberCount = (password.match(/[0-9]/g) || []).length;
  const symbolCount = (password.match(/[^a-zA-Z0-9]/g) || []).length;

  let poolSize = 0;
  if (lowerCount > 0) poolSize += 26;
  if (upperCount > 0) poolSize += 26;
  if (numberCount > 0) poolSize += 10;
  if (symbolCount > 0) poolSize += 33;
  if (poolSize === 0) poolSize = 10;

  // Combinatorial entropy: L * log2(poolSize)
  const theoreticalEntropy = length * Math.log2(poolSize);
  const shannonBits = calculateShannonEntropy(password);

  // Pattern and vulnerability detections
  const hasSequentialLetters = findSequentialAlphabet(password);
  const hasSequentialNumbers = findSequentialNumbers(password);
  const hasKeyboardSequence = findKeyboardSequence(password);
  const hasRepeatedChars = findRepeatedChars(password);
  const hasYearPattern = findYearPattern(password);

  // Common dictionary & leet-speak detection
  const normalizedLower = password.toLowerCase();
  const decodedLeet = decodeLeet(password);
  const isDirectCommon = COMMON_PASSWORDS.has(normalizedLower);
  const isLeetCommon = COMMON_PASSWORDS.has(decodedLeet);
  const containsCommonWord = Array.from(COMMON_PASSWORDS).some(
    (w) => w.length >= 5 && (normalizedLower.includes(w) || decodedLeet.includes(w))
  );

  const isPassphrase = isPassphraseCandidate(password);

  // ── Scoring Calculation (0 to 100) ──────────────────────────────────────────
  let rawScore = 0;

  // 1. Length points (up to 45 pts)
  if (length >= 20) rawScore += 45;
  else if (length >= 16) rawScore += 40;
  else if (length >= 14) rawScore += 34;
  else if (length >= 12) rawScore += 26;
  else if (length >= 10) rawScore += 18;
  else if (length >= 8) rawScore += 10;
  else rawScore += Math.max(0, length * 1.2);

  // 2. Character diversity points (up to 30 pts)
  let varietyCount = 0;
  if (lowerCount > 0) varietyCount++;
  if (upperCount > 0) varietyCount++;
  if (numberCount > 0) varietyCount++;
  if (symbolCount > 0) varietyCount++;

  if (varietyCount === 4) rawScore += 30;
  else if (varietyCount === 3) rawScore += 20;
  else if (varietyCount === 2) rawScore += 10;
  else rawScore += 2;

  // 3. Shannon Entropy Bonus (up to 25 pts)
  if (shannonBits > 65) rawScore += 25;
  else if (shannonBits > 50) rawScore += 18;
  else if (shannonBits > 35) rawScore += 10;
  else if (shannonBits > 20) rawScore += 5;

  // 4. Passphrase Bonus: reward long multi-word phrases even if lacking symbols
  if (isPassphrase) {
    rawScore += 25;
  }

  // ── Deductions & Penalties ──────────────────────────────────────────────────
  const warnings = [];
  const suggestions = [];
  const strengths = [];

  if (isDirectCommon) {
    rawScore = Math.min(rawScore, 10);
    warnings.push('This is an extremely common, widely leaked password.');
    suggestions.push('Never use easily guessed words like "password" or "123456".');
  } else if (isLeetCommon) {
    rawScore = Math.min(rawScore, 20);
    warnings.push('Predictable substitution detected (e.g. replacing "o" with "0" or "a" with "@").');
    suggestions.push('Automated cracking tools test common substitutions instantly.');
  } else if (containsCommonWord) {
    rawScore -= 20;
    warnings.push('Contains a common dictionary word or leaked fragment.');
  }

  if (hasSequentialNumbers) {
    rawScore -= 15;
    warnings.push('Sequential number sequence detected (e.g., 1234, 9876).');
  }

  if (hasSequentialLetters) {
    rawScore -= 15;
    warnings.push('Sequential alphabet sequence detected (e.g., abc, xyz).');
  }

  if (hasKeyboardSequence) {
    rawScore -= 18;
    warnings.push('Keyboard walk sequence detected (e.g., qwerty, asdfgh).');
  }

  if (hasRepeatedChars) {
    rawScore -= 12;
    warnings.push('Repeated identical characters detected (e.g., aaa, 111).');
  }

  if (hasYearPattern) {
    rawScore -= 10;
    warnings.push('Contains a four-digit year pattern (e.g. 1998, 2024).');
  }

  // Length suggestions & strengths
  if (length < 8) {
    warnings.push('Critically short length (< 8 characters).');
    suggestions.push('Increase length to at least 12-16 characters.');
  } else if (length < 12) {
    suggestions.push('Consider adding 4+ more characters to increase entropy exponentially.');
  } else if (length >= 16) {
    strengths.push('Excellent length provides high mathematical resistance.');
  }

  if (varietyCount >= 4) {
    strengths.push('Complete character set diversity (uppercase, lowercase, numbers, symbols).');
  } else if (varietyCount < 3 && !isPassphrase) {
    suggestions.push('Mix character categories (uppercase, numbers, symbols).');
  }

  if (isPassphrase) {
    strengths.push('Strong passphrase structure: high entropy and easy to remember.');
  }

  if (!hasKeyboardSequence && !hasSequentialNumbers && !hasSequentialLetters && !hasRepeatedChars && length >= 12) {
    strengths.push('No predictable sequences or repeating keyboard patterns found.');
  }

  // Ensure score stays within 0 - 100
  const finalScore = Math.max(5, Math.min(100, Math.round(rawScore)));

  // ── Determine Strength Tier & Color ─────────────────────────────────────────
  let label = 'Very Weak';
  let color = 'rose';
  let themeKey = 'very_weak';

  if (finalScore >= 85) {
    label = 'Very Strong';
    color = 'emerald';
    themeKey = 'very_strong';
  } else if (finalScore >= 68) {
    label = 'Strong';
    color = 'cyan';
    themeKey = 'strong';
  } else if (finalScore >= 45) {
    label = 'Moderate';
    color = 'amber';
    themeKey = 'moderate';
  } else if (finalScore >= 25) {
    label = 'Weak';
    color = 'orange';
    themeKey = 'weak';
  } else {
    label = 'Very Weak';
    color = 'rose';
    themeKey = 'very_weak';
  }

  // ── Crack Time Estimation ──────────────────────────────────────────────────
  // Effective entropy factoring in penalties
  const effectiveEntropy = Math.max(1, theoreticalEntropy * (finalScore / 100));
  const totalGuesses = Math.pow(2, effectiveEntropy);

  // Scenarios:
  // 1. Online throttled rate: 1,000 attempts/sec
  const onlineSeconds = totalGuesses / (1000 * 2);
  // 2. Slow hash (bcrypt / Argon2 on high-end rig): 10,000 attempts/sec
  const slowHashSeconds = totalGuesses / (10000 * 2);
  // 3. Fast hash (MD5 / NTLM cluster on modern GPUs): 100 billion (1e11) attempts/sec
  const fastGpuSeconds = totalGuesses / (1e11 * 2);

  const crackTimes = {
    online: formatCrackTime(onlineSeconds),
    slowHash: formatCrackTime(slowHashSeconds),
    fastGpu: formatCrackTime(fastGpuSeconds),
  };

  // Structured indicators for UI Checklist & Analysis
  const indicators = [
    {
      id: 'length',
      label: 'Password Length',
      value: `${length} characters`,
      passed: length >= 12,
      critical: length < 8,
      status: length >= 16 ? 'Optimal (16+)' : length >= 12 ? 'Adequate (12+)' : 'Too Short',
      info: 'Length is the single most powerful factor against brute-force attacks.',
    },
    {
      id: 'diversity',
      label: 'Character Diversity',
      value: `${varietyCount} of 4 categories`,
      passed: varietyCount >= 3 || isPassphrase,
      critical: varietyCount <= 1 && !isPassphrase,
      status: varietyCount === 4 ? 'All 4 types used' : `${varietyCount} types used`,
      info: 'Using lowercase, uppercase, digits, and symbols expands the search pool.',
    },
    {
      id: 'dictionary',
      label: 'Dictionary & Leet Check',
      value: isDirectCommon ? 'Leaked Password' : isLeetCommon ? 'Leet Pattern' : 'Clean',
      passed: !isDirectCommon && !isLeetCommon && !containsCommonWord,
      critical: isDirectCommon || isLeetCommon,
      status: isDirectCommon ? 'Known Common Password' : isLeetCommon ? 'Predictable Leet-speak' : 'No common words found',
      info: 'Attackers test lists of known passwords and common words first.',
    },
    {
      id: 'sequences',
      label: 'Sequence & Keyboard Walk',
      value: hasKeyboardSequence || hasSequentialNumbers || hasSequentialLetters ? 'Detected' : 'None',
      passed: !hasKeyboardSequence && !hasSequentialNumbers && !hasSequentialLetters,
      critical: hasKeyboardSequence,
      status: hasKeyboardSequence ? 'QWERTY keyboard walk' : hasSequentialNumbers ? 'Sequential numbers' : 'No sequential patterns',
      info: 'Patterns like "123456" or "qwerty" are prioritized by cracking tools.',
    },
    {
      id: 'repetition',
      label: 'Repeated Characters',
      value: hasRepeatedChars ? 'Repeats found' : 'No repeats',
      passed: !hasRepeatedChars,
      critical: false,
      status: hasRepeatedChars ? 'Repeated characters (e.g. aaa)' : 'Well diversified',
      info: 'Repeating consecutive characters lowers entropy.',
    },
    {
      id: 'entropy',
      label: 'Information Entropy',
      value: `${shannonBits} bits`,
      passed: shannonBits >= 45,
      critical: shannonBits < 25,
      status: shannonBits >= 60 ? 'High randomness' : shannonBits >= 40 ? 'Moderate' : 'Low randomness',
      info: 'Shannon entropy measures character unpredictability mathematically.',
    },
  ];

  return {
    isEmpty: false,
    score: finalScore,
    scorePercent: finalScore,
    label,
    color,
    themeKey,
    length,
    charSets: {
      lowercase: lowerCount,
      uppercase: upperCount,
      numbers: numberCount,
      symbols: symbolCount,
    },
    poolSize,
    entropyBits: Math.round(theoreticalEntropy * 10) / 10,
    shannonBits,
    isPassphrase,
    crackTimes,
    indicators,
    suggestions: suggestions.length > 0 ? suggestions : ['This password exhibits strong characteristics and diverse entropy.'],
    warnings,
    strengths,
  };
};
