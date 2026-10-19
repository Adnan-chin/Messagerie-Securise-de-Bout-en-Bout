import { describe, test, expect } from 'vitest';
import { generateIdentity } from '../../client/src/crypto/keygen.js';
// Étape 2 : adapter
import { signChallenge } from '../../client/src/crypto/signatures.js';
// Étape 2 : adapter
import { toB64, fromB64, toWire, fromWire } from
    '../../client/src/crypto/encoding.js';
import {
    HS_FIELDS, initiatorHello, responderOnHello, initiatorOnResponse,
    responderOnFinish,
} from '../../client/src/crypto/handshake.js';
const API = process.env.API ?? 'http://localhost:3000';
const WS = API.replace('http', 'ws') + '/ws';
const post = async (path, body) => (await fetch(API + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body:
        JSON.stringify(body),
})).json();
async function createUser() {
    const id = generateIdentity();
    const username = 'u' + Math.random().toString(36).slice(2, 10);
    await post('/auth/register', {
        username, sign_pub: toB64(id.signPub),
        x25519_pub: toB64(id.xPub),
        kem_pub: toB64(id.kemPub), bundle_sig: toB64(id.bundleSig)
    });
    const { nonce } = await post('/auth/challenge', { username });
    const signature = toB64(signChallenge(fromB64(nonce), username,
        id.signPriv));
    const { token } = await post('/auth/verify', {
        username, nonce, signature
    });

    return { id, username, token };
}
function openSocket(token) {
    return new Promise((resolve) => {
        const ws = new WebSocket(WS), queue = [], waiters = [];
        ws.onmessage = (e) => {
            const f = JSON.parse(e.data); const w =
                waiters.shift(); w ? w(f) : queue.push(f);
        };
        ws.onopen = () => ws.send(JSON.stringify({ type: 'auth', token }));
        const next = () => new Promise((res) => {
            const f = queue.shift(); f ?
                res(f) : waiters.push(res);
        });
        next().then(() => resolve({ ws, next }));            // première trame = 
        auth_ok
    });
}
async function setup() {
    const A = await createUser(), B = await createUser();
    return {
        A, B, sa: await openSocket(A.token), sb: await
            openSocket(B.token),
        meA: { signPub: A.id.signPub, signPriv: A.id.signPriv }, peerA: {
            signPub: A.id.signPub
        },
        meB: { signPub: B.id.signPub, signPriv: B.id.signPriv }, peerB: {
            signPub: B.id.signPub
        }
    };
}
describe.skipIf(!process.env.E2E)('handshake à travers le vrai serveur', () => {
    test('Alice et Bob dérivent la même root_key', async () => {
        const { A, B, sa, sb, meA, peerA, meB, peerB } = await setup();
        const h = initiatorHello({ me: meA, peer: peerB });
        sa.ws.send(JSON.stringify(toWire('hs_hello', B.username, h.wire)));
        const f1 = await sb.next();
        expect(f1.type).toBe('hs_hello');
        expect(f1.from).toBe(A.username);                    // `from` ajouté par le serveur
        const r = responderOnHello({
            me: meB, peer: peerA, hello: fromWire(f1,
                HS_FIELDS.hs_hello)
        });
        sb.ws.send(JSON.stringify(toWire('hs_response', A.username, r.wire)));
        const f2 = await sa.next();
        const a = initiatorOnResponse({
            me: meA, peer: peerB, state: h.state,

            resp: fromWire(f2, HS_FIELDS.hs_response)
        });
        sa.ws.send(JSON.stringify(toWire('hs_finish', B.username, a.wire)));
        const f3 = await sb.next();
        const b = responderOnFinish({
            me: meB, peer: peerA, state: r.state,
            fin: fromWire(f3, HS_FIELDS.hs_finish)
        });
        expect(b.root).toEqual(a.root);
        sa.ws.close(); sb.ws.close();
    }, 20000);
    test('le serveur refuse une clé de mauvaise taille', async () => {
        const { B, sa, meA, peerB } = await setup();
        const h = initiatorHello({ me: meA, peer: peerB });
        sa.ws.send(JSON.stringify(toWire('hs_hello', B.username, {
            ...h.wire,
            eA_pub: h.wire.eA_pub.slice(0, 31)
        })));
        expect((await sa.next()).code).toBe('INVALID_SIZE');
        sa.ws.close();
    }, 20000);
    test('trame avant authentification : fermeture 4401', async () => {
        const ws = new WebSocket(WS);
        const code = await new Promise((res) => {
            ws.onopen = () => ws.send(JSON.stringify({ type: 'hs_hello' }));
            ws.onclose = (e) => res(e.code);
        });
        expect(code).toBe(4401);
    });
});