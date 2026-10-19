import { utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';

export { utf8ToBytes, concatBytes };

/** Comparaison a temps constant (pas de sortie anticipee dependant des donnees). */
export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Verifie qu'une valeur est un Uint8Array de la taille attendue (sinon exception). */
export function assertBytes(value, length, name = 'valeur') {
  if (!(value instanceof Uint8Array)) throw new TypeError(`${name} doit etre un Uint8Array`);
  if (length !== undefined && value.length !== length) {
    throw new RangeError(`${name} : taille ${value.length} octets, ${length} attendus`);
  }
  return value;
}

/** Encode un entier 32 bits en big-endian (prefixe de longueur). */
function u32(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

/**
 * Encodage canonique et non ambigu : chaque element est precede de sa longueur.
 * Evite que ("ab","c") et ("a","bc") donnent les memes octets a signer.
 */
export function encodeParts(...parts) {
  const out = [];
  for (const p of parts) {
    const bytes = typeof p === 'string' ? utf8ToBytes(p) : p;
    assertBytes(bytes, undefined, 'element a encoder');
    out.push(u32(bytes.length), bytes);
  }
  return concatBytes(...out);
}