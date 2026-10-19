import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';


export const toB64 = (u8) => btoa(String.fromCharCode(...u8));
export const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));


export const uuidToBytes = (u) => hexToBytes(u.replaceAll('-', ''));
export function bytesToUuid(b) {
    const h = bytesToHex(b);
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Octets -> trame JSON */
export function toWire(type, to, fields) {
    const out = { type, to };
    for (const [k, v] of Object.entries(fields)) out[k] = k === 'sid' ? bytesToUuid(v) : toB64(v);
    return out;
}
/** Trame JSON -> octets */
export function fromWire(frame, keys) {
    const out = {};
    for (const k of keys) {
    if (typeof frame[k] !== 'string') throw new Error(`champ manquant : ${k}`);
    out[k] = k === 'sid' ? uuidToBytes(frame[k]) : fromB64(frame[k]);
}
return out;
}