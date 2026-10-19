import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { expectLen } from './transcript.js';

const INFO_ROOT = utf8ToBytes('secure-messenger/v1/root');

export function combine(ssMlkem, ssX25519, transcriptBytes) {
    expectLen(ssMlkem, 32, 'ss_mlkem');
    expectLen(ssX25519, 32, 'ss_x25519');
    const ikm = concatBytes(ssMlkem, ssX25519);        // ML-KEM d'abord, puis X25519
    const root = hkdf(sha256, ikm, sha256(transcriptBytes), INFO_ROOT, 32);
    ikm.fill(0);                                      // hygiène mémoire
    return root
}                                   
