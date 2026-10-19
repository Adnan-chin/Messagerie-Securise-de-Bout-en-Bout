import { describe, test, expect } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import {initiatorHello, responderOnHello, initiatorOnResponse, responderOnFinish,} from '../../client/src/crypto/handshake.js';
import { safetyNumber } from '../../client/src/crypto/fingerprint.js';


const identity = () => {
    const signPriv = crypto.getRandomValues(new Uint8Array(32));
    return { signPriv, signPub: ed25519.getPublicKey(signPriv) };
};
const flip = (u8) => { const c = u8.slice(); c[0] ^= 1; return c; };

// Déroule les 3 messages ; `tamper` permet de modifier un message « sur le réseau
function run(alice, bob, tamper = {}) {
    const h = initiatorHello({ me: alice, peer: { signPub: bob.signPub } });
    const hello = tamper.hello ? tamper.hello(h.wire) : h.wire;
    const r = responderOnHello({
        me: bob, peer: { signPub: alice.signPub },
        hello
    });
    const resp = tamper.resp ? tamper.resp(r.wire) : r.wire;
    const a = initiatorOnResponse({
        me: alice, peer: { signPub: tamper.fakePeer ?? bob.signPub }, state:
            h.state, resp
    });
    const fin = tamper.fin ? tamper.fin(a.wire) : a.wire;
    const b = responderOnFinish({
        me: bob, peer: { signPub: alice.signPub },
        state: r.state, fin
    });
    return { rootA: a.root, rootB: b.root, hState: h.state, rState: r.state };
}
describe('handshake hybride', () => {
    const alice = identity(), bob = identity();
    test('les deux parties dérivent la même root_key de 32 octets', () => {
        const { rootA, rootB } = run(alice, bob);
        expect(rootA).toHaveLength(32);
        expect(rootA).toEqual(rootB);
    });
    test('deux handshakes successifs donnent des clés différentes', () => {
        expect(run(alice, bob).rootA).not.toEqual(run(alice, bob).rootA);
    });
    test('les secrets éphémères sont effacés', () => {
        const { hState, rState } = run(alice, bob);
        expect(hState.eA.every((b) => b === 0)).toBe(true);
        expect(rState.eB.every((b) => b === 0)).toBe(true);
        expect(rState.dkB.every((b) => b === 0)).toBe(true);
    });
    test('serveur malveillant : eA_pub remplacée', () => {
        expect(() => run(alice, bob, {
            hello: (w) => ({
                ...w, eA_pub:
                    flip(w.eA_pub)
            })
        }))
            .toThrow(/Signature invalide/);
    });
    test('serveur malveillant : eB_pub remplacée', () => {
        expect(() => run(alice, bob, {
            resp: (w) => ({
                ...w, eB_pub:
                    flip(w.eB_pub)
            })
        }))
            .toThrow(/Signature invalide/);
    });
    test('serveur malveillant : ekB remplacée', () => {
        expect(() => run(alice, bob, {
            resp: (w) => ({ ...w, ekB: flip(w.ekB) })
        }))
            .toThrow(/Signature invalide/);
    });
    test('serveur malveillant : ct remplacé', () => {
        expect(() => run(alice, bob, { fin: (w) => ({ ...w, ct: flip(w.ct) }) }))
            .toThrow(/Signature invalide/);
    });
    test('réponse signée par une autre identité que celle attendue', () => {
        expect(() => run(alice, bob, {
            fakePeer: identity().signPub
        })).toThrow(/Signature invalide/);
    });
    test('taille incorrecte rejetée avant tout calcul', () => {
        expect(() => run(alice, bob, {
            hello: (w) => ({
                ...w, eA_pub:
                    w.eA_pub.slice(0, 31)
            })
        }))
            .toThrow(/taille invalide/);
    });
});
describe('empreinte de sécurité', () => {
    test('identique des deux côtés, 12 groupes de 5 chiffres, dépend des identités', () => {
        const a = identity(), b = identity(), c = identity();
        expect(safetyNumber(a.signPub, b.signPub)).toBe(safetyNumber(b.signPub,
            a.signPub));
        expect(safetyNumber(a.signPub, b.signPub)).toMatch(/^(\d{5} ){11}\d{5}$/);
        expect(safetyNumber(a.signPub,
            b.signPub)).not.toBe(safetyNumber(a.signPub, c.signPub));
    });
});