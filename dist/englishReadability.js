/**
 * Strict checks for "readable English" to reduce false positives from random ASCII.
 * Uses a common-word set + letter/ASCII statistics (not a full NLP model).
 */
/** Lowercase tokens, length >= 2 — curated high-frequency English (subset). */
const RAW_WORDS = `
the be to of and a in that have i it for not on with he as you do at this but his by from they we say her she or an will my one all would there their what so up out if about who get which go me when make can like time no just him know take people into year your good some could them see other than then now look only come its over think also back after use two how our work first well way even new want because any these give day most us is is
the and for are but not you all can had her was one our out day get has him his how man new now old see two way who boy did its let put say she too use any may say
that with have this will from they know been were said each which their time would there could about other many then them these think where being also those under years
after before between through during against among within without another against
when what whom whose which while where why
shall should would could might must will can need
into onto upon over upon
mountain house return frozen honor warrior city fires last kind cell below waves infinite finished
when finished we will return house infinite honor suffers searched frozen
call duty black ops giant der riese treyarch zombies richtofen maxis samantha monty primis ultimis
`.split(/\s+/).filter((w) => w.length >= 2);
export const WORD_SET = new Set(RAW_WORDS.map((w) => w.toLowerCase()));
/** For word-position scanning (min length 3 to reduce noise). */
export function getDictionaryWordSet() {
    return WORD_SET;
}
const COMMON_QUADGRAMS = {};
// Top English quadgrams (log10 probabilities × 10, shifted) — condensed from standard tables
const Q4 = [
    "TION", "NTHE", "THER", "THAT", "HERE", "ATED", "IONS", "ATIO", "IGHT", "STHE",
    "OTHE", "ANDT", "EDTH", "THEM", "FTHE", "THES", "WITH", "MENT", "IONS", "THIS",
    "INGT", "NGTH", "OUGH", "HAVE", "FROM", "OULD", "OUGH", "WERE", "HING", "ENCE",
    "ONTH", "THEY", "TING", "HEIR", "OULD", "NTHE", "SAND", "CTHE", "EVER", "TTHE",
    "EAND", "THIN", "WILL", "HECO", "HEIN", "ATHE", "HEWAS", "NAND", "EING", "INGE",
];
for (const q of Q4) {
    COMMON_QUADGRAMS[q] = (COMMON_QUADGRAMS[q] ?? 0) + 1;
}
function chiSquaredEnglish(upper) {
    const ENGLISH_FREQ = {
        A: 0.08167, B: 0.01492, C: 0.02782, D: 0.04253, E: 0.12702, F: 0.02228,
        G: 0.02015, H: 0.06094, I: 0.06966, J: 0.00153, K: 0.00772, L: 0.04025,
        M: 0.02406, N: 0.06749, O: 0.07507, P: 0.01929, Q: 0.00095, R: 0.05987,
        S: 0.06327, T: 0.09056, U: 0.02758, V: 0.00978, W: 0.0236, X: 0.0015,
        Y: 0.01974, Z: 0.00074,
    };
    let letters = 0;
    const counts = new Map();
    for (const ch of upper) {
        if (ch >= "A" && ch <= "Z") {
            counts.set(ch, (counts.get(ch) ?? 0) + 1);
            letters++;
        }
    }
    if (letters < 8)
        return 1e6;
    let chi = 0;
    for (const [letter, exp] of Object.entries(ENGLISH_FREQ)) {
        const observed = counts.get(letter) ?? 0;
        const expected = exp * letters;
        const d = observed - expected;
        chi += (d * d) / expected;
    }
    return chi;
}
function countDictWords(text) {
    const lower = text.toLowerCase();
    const tokens = lower.split(/[^a-z]+/).filter((t) => t.length >= 2);
    let hits = 0;
    for (const t of tokens) {
        if (WORD_SET.has(t))
            hits++;
    }
    return { hits, tokens: Math.max(1, tokens.length) };
}
function quadgramHitRatio(upper) {
    if (upper.length < 4)
        return 0;
    let hits = 0;
    const max = upper.length - 3;
    for (let i = 0; i < max; i++) {
        const q = upper.slice(i, i + 4);
        if (COMMON_QUADGRAMS[q])
            hits++;
    }
    return hits / max;
}
/**
 * True only if text looks like sustained English: mostly ASCII letters/spaces,
 * dictionary hits, letter distribution not absurd, quadgram-ish signal.
 */
export function isFullyEnglishReadable(text, minLen = 48) {
    const r = analyzeEnglishReadability(text, minLen);
    return r.passes;
}
export function analyzeEnglishReadability(text, minLen = 48) {
    const reasons = [];
    if (text.length < minLen) {
        reasons.push(`too_short(<${minLen})`);
        return fail(text, reasons);
    }
    let ascii = 0;
    let letters = 0;
    for (let i = 0; i < text.length; i++) {
        const c = text.charCodeAt(i);
        if (c <= 127)
            ascii++;
        if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122))
            letters++;
    }
    const asciiRatio = ascii / text.length;
    const letterRatio = letters / text.length;
    const upper = text.toUpperCase().replace(/[^A-Z]/g, "");
    const chiSq = upper.length >= 8 ? chiSquaredEnglish(upper) : 1e6;
    const { hits, tokens } = countDictWords(text);
    const dictWordRatio = hits / tokens;
    const qHit = upper.length >= 4 ? quadgramHitRatio(upper) : 0;
    const passes = asciiRatio >= 0.97 &&
        letterRatio >= 0.52 &&
        chiSq <= 90 &&
        hits >= 12 &&
        dictWordRatio >= 0.12 &&
        qHit >= 0.012;
    if (asciiRatio < 0.97)
        reasons.push("non_ascii");
    if (letterRatio < 0.52)
        reasons.push("low_letters");
    if (chiSq > 90)
        reasons.push(`chi_sq_${chiSq.toFixed(0)}`);
    if (hits < 12)
        reasons.push("few_dict_words");
    if (dictWordRatio < 0.12)
        reasons.push("low_dict_ratio");
    if (qHit < 0.012)
        reasons.push("low_quadgrams");
    return {
        passes,
        asciiRatio,
        letterRatio,
        dictWordHits: hits,
        dictWordRatio,
        quadgramHits: qHit,
        chiSq,
        reasons: passes ? [] : reasons,
    };
}
function fail(text, reasons) {
    let ascii = 0;
    let letters = 0;
    for (let i = 0; i < text.length; i++) {
        const c = text.charCodeAt(i);
        if (c <= 127)
            ascii++;
        if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122))
            letters++;
    }
    const upper = text.toUpperCase().replace(/[^A-Z]/g, "");
    const chiSq = upper.length >= 8 ? chiSquaredEnglish(upper) : 1e6;
    const { hits, tokens } = countDictWords(text);
    return {
        passes: false,
        asciiRatio: text.length ? ascii / text.length : 0,
        letterRatio: text.length ? letters / text.length : 0,
        dictWordHits: hits,
        dictWordRatio: hits / Math.max(1, tokens),
        quadgramHits: upper.length >= 4 ? quadgramHitRatio(upper) : 0,
        chiSq,
        reasons,
    };
}
/** Higher = closer to English (for ranking when nothing passes strict gate). */
export function englishReadabilityRank(text) {
    const r = analyzeEnglishReadability(text, 8);
    return (r.dictWordHits * 12 +
        r.dictWordRatio * 80 +
        r.asciiRatio * 30 +
        r.letterRatio * 25 +
        r.quadgramHits * 200 -
        Math.min(r.chiSq, 500) * 0.08);
}
