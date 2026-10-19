import { ed25519 } from '@noble/curves/ed25519.js';
import { SIZES } from './keygen.js';
import { assertBytes, concatBytes, encodeParts, utf8ToBytes } from './bytes.js';

const AUTH_CONTEXT = 'auth-v1';

/** Signature du defi serveur : "auth-v1" || nonce || username (separation de contexte). */
export function signChallenge(nonce, username, signPriv) {
  assertBytes(nonce, 32, 'nonce');
  const msg = concatBytes(utf8ToBytes(AUTH_CONTEXT), nonce, utf8ToBytes(username));
  return ed25519.sign(msg, signPriv); // 64 octets
}

export function verifyChallenge(signature, nonce, username, signPub) {
  const msg = concatBytes(utf8ToBytes(AUTH_CONTEXT), nonce, utf8ToBytes(username));
  return safeVerify(signature, msg, signPub);
}

/** Verifie le bundle d'un contact : sig = Ed25519(x25519_pub || kem_pub). A faire AVANT tout handshake. */
export function verifyBundle({ signPub, xPub, kemPub, bundleSig }) {
  try {
    assertBytes(signPub, SIZES.ED_PUB, 'signPub');
    assertBytes(xPub, SIZES.X_PUB, 'xPub');
    assertBytes(kemPub, SIZES.KEM_PUB, 'kemPub');
    assertBytes(bundleSig, SIZES.ED_SIG, 'bundleSig');
  } catch {
    return false;
  }
  return safeVerify(bundleSig, concatBytes(xPub, kemPub), signPub);
}

/**
 * Signe un message de protocole (handshake, rekey). Les elements sont encodes avec leur
 * longueur : signTranscript(priv, 'hs-1', sid, ePub) ne peut pas etre confondu avec un autre decoupage.
 */
export function signTranscript(signPriv, label, ...parts) {
  return ed25519.sign(encodeParts(label, ...parts), signPriv);
}

export function verifyTranscript(signature, signPub, label, ...parts) {
  return safeVerify(signature, encodeParts(label, ...parts), signPub);
}

/** verify() peut lever une exception sur une entree mal formee : on renvoie toujours un booleen. */
function safeVerify(signature, msg, pub) {
  try {
    return ed25519.verify(signature, msg, pub);
  } catch {
    return false;
  }
}