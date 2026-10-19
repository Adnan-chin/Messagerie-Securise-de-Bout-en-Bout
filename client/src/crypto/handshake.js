import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { combine } from './hybrid.js';
import { uuidToBytes } from './encoding.js';
import { SIZE, expectLen, same, msgHs1, msgHs2, msgHs3, transcript } from'./transcript.js';

export const HS_FIELDS = {
    hs_hello: ['sid', 'eA_pub', 'sigA'],
    hs_response: ['sid', 'eB_pub', 'ekB', 'sigB'],
    hs_finish: ['sid', 'ct', 'sigA2'],
};

const rand32 = () => crypto.getRandomValues(new Uint8Array(32));

function mustVerify(sig, msg, pub, label) {
    let ok = false;
    try { ok = ed25519.verify(sig, msg, pub); } catch { ok = false; }
    if (!ok) throw new Error(`Signature invalide (${label})`);
}

// me = { signPub, signPriv } ; peer = { signPub } (clé Ed25519 déjà vérifiée via le bundle)
// ---- Message 1 : Alice -> Bob ----
export function initiatorHello({ me, peer }) {
    const sid = uuidToBytes(crypto.randomUUID());
    const eA = rand32();
    const eA_pub = x25519.getPublicKey(eA);
    const sigA = ed25519.sign(msgHs1(sid, me.signPub, peer.signPub, eA_pub),
        me.signPriv);
    return { state: { sid, eA, eA_pub }, wire: { sid, eA_pub, sigA } };
}
// ---- Message 2 : Bob -> Alice ----
export function responderOnHello({ me, peer, hello }) {
    expectLen(hello.sid, SIZE.sid, 'sid');
    expectLen(hello.eA_pub, SIZE.x, 'eA_pub');
    expectLen(hello.sigA, SIZE.sig, 'sigA');
    mustVerify(hello.sigA, msgHs1(hello.sid, peer.signPub, me.signPub,
        hello.eA_pub), peer.signPub, 'hs-1');
    const eB = rand32();
    const eB_pub = x25519.getPublicKey(eB);
    const kem = ml_kem768.keygen();                    // paire KEM ÉPHÉMÈRE
    const sigB = ed25519.sign(
        msgHs2(hello.sid, peer.signPub, me.signPub, hello.eA_pub, eB_pub,
            kem.publicKey), me.signPriv);
    return {
        state: {
            sid: hello.sid, eA_pub: hello.eA_pub, eB, eB_pub, dkB:
                kem.secretKey, ekB: kem.publicKey
        },
        wire: { sid: hello.sid, eB_pub, ekB: kem.publicKey, sigB },
    };
}
// ---- Message 3 : Alice -> Bob (et calcul de la racine côté Alice) ----
export function initiatorOnResponse({ me, peer, state, resp }) {
    if (!same(resp.sid, state.sid)) throw new Error('sid inattendu');
    expectLen(resp.eB_pub, SIZE.x, 'eB_pub');
    expectLen(resp.ekB, SIZE.ek, 'ekB');
    expectLen(resp.sigB, SIZE.sig, 'sigB');
    mustVerify(resp.sigB,

        msgHs2(state.sid, me.signPub, peer.signPub, state.eA_pub, resp.eB_pub,
            resp.ekB),
        peer.signPub, 'hs-2');
    const ssX = x25519.getSharedSecret(state.eA, resp.eB_pub);
    const { cipherText: ct, sharedSecret: ssK } =
        ml_kem768.encapsulate(resp.ekB);
    const args = [state.sid, me.signPub, peer.signPub, state.eA_pub,
    resp.eB_pub, resp.ekB, ct];
    const root = combine(ssK, ssX, transcript(...args));
    const sigA2 = ed25519.sign(msgHs3(...args), me.signPriv);
    ssX.fill(0); ssK.fill(0); state.eA.fill(0);
    // effacement des secrets éphémères
    return { root, wire: { sid: state.sid, ct, sigA2 } };
}
// ---- Réception du message 3 : Bob calcule la racine ----
export function responderOnFinish({ me, peer, state, fin }) {
    if (!same(fin.sid, state.sid)) throw new Error('sid inattendu');
    expectLen(fin.ct, SIZE.ct, 'ct');
    expectLen(fin.sigA2, SIZE.sig, 'sigA2');
    const args = [state.sid, peer.signPub, me.signPub, state.eA_pub,
    state.eB_pub, state.ekB, fin.ct];
    mustVerify(fin.sigA2, msgHs3(...args), peer.signPub, 'hs-3');
    const ssX = x25519.getSharedSecret(state.eB, state.eA_pub);
    const ssK = ml_kem768.decapsulate(fin.ct, state.dkB);
    const root = combine(ssK, ssX, transcript(...args));
    ssX.fill(0); ssK.fill(0); state.eB.fill(0); state.dkB.fill(0);
    return { root };
}