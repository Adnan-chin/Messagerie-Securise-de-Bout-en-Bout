import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { concatBytes } from './bytes.js';

export const SIZES = Object.freeze({
  ED_PUB: 32, ED_PRIV: 32, ED_SIG: 64,
  X_PUB: 32, X_PRIV: 32,
  KEM_PUB: 1184, KEM_PRIV: 2400, KEM_CT: 1088, KEM_SS: 32,
});

/**
 * Genere l'identite long-terme : Ed25519 (signature) + X25519 + ML-KEM-768 (echange),
 * et signe le bundle (x25519_pub || kem_pub) avec la cle d'identite.
 */
export function generateIdentity() {
  const sign = ed25519.keygen();        // { secretKey, publicKey }
  const dh = x25519.keygen();           // { secretKey, publicKey }
  const kem = ml_kem768.keygen();       // { publicKey (1184 o), secretKey (2400 o) }
  const bundleSig = ed25519.sign(concatBytes(dh.publicKey, kem.publicKey), sign.secretKey);
  return {
    signPriv: sign.secretKey, signPub: sign.publicKey,
    xPriv: dh.secretKey, xPub: dh.publicKey,
    kemPriv: kem.secretKey, kemPub: kem.publicKey,
    bundleSig,
  };
}

/** Partie publique, la seule qui part vers le serveur (POST /auth/register). */
export function publicBundle(identity) {
  const { signPub, xPub, kemPub, bundleSig } = identity;
  return { signPub, xPub, kemPub, bundleSig };
}