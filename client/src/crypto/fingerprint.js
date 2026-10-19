import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/hashes/utils.js';


function cmp(a, b) {
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
    return 0;
}
/** 12 groupes de 5 chiffres (60 chiffres), identiques pour Alice et Bob. */
export function safetyNumber(idA, idB) {
    const [lo, hi] = cmp(idA, idB) <= 0 ? [idA, idB] : [idB, idA];
    const h = sha256(concatBytes(lo, hi));
    const groups = [];
    for (let i = 0; i < 12; i++) {
        groups.push(String(((h[2 * i] << 8) | h[2 * i + 1]) % 100000).padStart(5,
            '0'));
    }
    return groups.join(' ');
}