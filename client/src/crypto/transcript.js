import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';


export const SIZE = { sid: 16, x: 32, sig: 64, ek: 1184, ct: 1088 };

export function expectLen(bytes, n, name) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== n) {
    throw new Error(`${name} : taille invalide (attendu ${n} octets)`);
}
}

export function same(a, b) {
    return a.length === b.length && a.every((v, i) => v === b[i]);
}

const tag = utf8ToBytes;

export const msgHs1 = (sid, idA, idB, eA) => concatBytes(tag('hs-1'), sid, idA, idB, eA);
export const msgHs2 = (sid, idA, idB, eA, eB, ekB) =>concatBytes(tag('hs-2'), sid, idA, idB, eA, eB, ekB);
export const transcript = (sid, idA, idB, eA, eB, ekB, ct) =>concatBytes(sid, idA, idB, eA, eB, ekB, ct);
export const msgHs3 = (...args) => concatBytes(tag('hs-3'), transcript(...args));