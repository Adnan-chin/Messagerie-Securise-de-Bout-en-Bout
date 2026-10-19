import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { SIZES } from './keygen.js';
import { assertBytes } from './bytes.js';

/** Paire ML-KEM-768 (ek = publicKey, dk = secretKey). */
export function kemKeygen() {
  const { publicKey, secretKey } = ml_kem768.keygen();
  return { ek: publicKey, dk: secretKey };
}

/** Initiateur : encapsule un secret vers la cle ek du repondeur. */
export function kemEncaps(ek) {
  assertBytes(ek, SIZES.KEM_PUB, 'ek');
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(ek);
  return { ct: cipherText, ss: sharedSecret };
}

/** Repondeur : retrouve le secret a partir de ct et de sa cle privee dk. */
export function kemDecaps(ct, dk) {
  assertBytes(ct, SIZES.KEM_CT, 'ct');
  assertBytes(dk, SIZES.KEM_PRIV, 'dk');
  return ml_kem768.decapsulate(ct, dk);
}