import { describe, test, expect } from 'vitest';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import sodium from 'libsodium-wrappers-sumo';


const seed = () => crypto.getRandomValues(new Uint8Array(32));
describe('librairies cryptographiques', () => {
  test('Ed25519 et X25519 : clés de 32 octets, signature de 64', () => {
    const s = seed();
    expect(ed25519.getPublicKey(s)).toHaveLength(32);
    expect(x25519.getPublicKey(seed())).toHaveLength(32);
    expect(ed25519.sign(new Uint8Array([1]), s)).toHaveLength(64);
  });
  test('ML-KEM-768 : tailles 1184 / 1088 / 32', () => {
    const { publicKey, secretKey } = ml_kem768.keygen();
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
    expect(publicKey).toHaveLength(1184);
    expect(cipherText).toHaveLength(1088);
    expect(ml_kem768.decapsulate(cipherText, 
secretKey)).toEqual(sharedSecret);
  });
  test('HKDF-SHA-256 sort 32 octets', () => {
    expect(hkdf(sha256, seed(), undefined, new Uint8Array([1]), 
32)).toHaveLength(32);
  });
  test('XChaCha20-Poly1305 : aller-retour', async () => {
    await sodium.ready;
    const key = seed(), nonce = sodium.randombytes_buf(24), aad = new 
Uint8Array([7]);
    const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      sodium.from_string('bonjour'), aad, null, nonce, key);
    const pt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, 
aad, nonce, key);
    expect(sodium.to_string(pt)).toBe('bonjour');
  });
});