import { useCallback, useEffect, useRef, useState } from 'react';

import {
  fromWire,
  toWire,
} from '../crypto/encoding.js';

import {
  HS_FIELDS,
  initiatorHello,
  responderOnHello,
  initiatorOnResponse,
  responderOnFinish,
} from '../crypto/handshake.js';

import { verifyBundle } from '../crypto/signatures.js';
import { loadIdentity } from '../crypto/keystore.js';
import { safetyNumber } from '../crypto/fingerprint.js';
import { connect } from '../services/socket.js';

const DEFAULT_API = 'http://localhost:3000';
const DEFAULT_SOCKET = 'ws://localhost:3000/ws';

const STATUS = {
  idle: {
    title: 'Non connecté',
    color: '#667085',
    description: 'Connectez-vous pour commencer le handshake.',
  },
  connecting: {
    title: 'Connexion en cours',
    color: '#667085',
    description: 'Connexion au serveur et vérification des clés publiques.',
  },
  handshaking: {
    title: 'Handshake en cours',
    color: '#b7791f',
    description: 'Les messages cryptographiques sont échangés.',
  },
  keyReady: {
    title: 'Clé calculée localement',
    color: '#b7791f',
    description:
      'Le client initiateur a envoyé hs_finish. Le protocole actuel ne prévoit pas d’accusé final confirmant que le pair l’a traité.',
  },
  secure: {
    title: 'Handshake vérifié',
    color: '#16803d',
    description:
      'Le client destinataire a vérifié hs_finish et calculé la clé de session.',
  },
  error: {
    title: 'Handshake échoué',
    color: '#b42318',
    description: 'La session n’est pas considérée comme sécurisée.',
  },
};

function decodeBundleValue(value, field) {
  if (value instanceof Uint8Array) {
    return value;
  }

  if (typeof value !== 'string') {
    throw new Error(`Clé publique invalide : champ ${field} manquant.`);
  }

  // Le serveur doit renvoyer les champs encodés en Base64.
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function normalizeBundle(json) {
  const bundle = json?.bundle ?? json?.keys ?? json;

  const result = {
    signPub: decodeBundleValue(bundle?.signPub, 'signPub'),
    xPub: decodeBundleValue(bundle?.xPub, 'xPub'),
    kemPub: decodeBundleValue(bundle?.kemPub, 'kemPub'),
    bundleSig: decodeBundleValue(bundle?.bundleSig, 'bundleSig'),
  };

  if (!verifyBundle(result)) {
    throw new Error(
      'La signature du bundle du contact est invalide. Handshake annulé.',
    );
  }

  return result;
}

function wipeHandshakeState(active) {
  if (!active?.state) return;

  for (const name of ['eA', 'eB', 'dkB']) {
    const value = active.state[name];

    if (value instanceof Uint8Array) {
      value.fill(0);
    }
  }
}

/**
 * ChatWindow : interface de test du handshake cryptographique.
 *
 * Props :
 * - currentUser : nom de l'utilisateur connecté
 * - peer        : nom du contact
 * - token       : JWT
 * - role        : "initiator" ou "responder"
 * - apiBase     : URL de l'API HTTP
 * - socketUrl   : URL du WebSocket
 *
 * L'identité locale doit déjà être enregistrée dans le keystore.
 *
 * IMPORTANT :
 * Ce composant ne chiffre ni ne transmet les messages de chat.
 * Il sert à intégrer et tester le handshake.
 */
export default function ChatWindow({
  currentUser,
  peer,
  token,
  role = 'initiator',
  apiBase = DEFAULT_API,
  socketUrl = DEFAULT_SOCKET,
}) {
  const [status, setStatus] = useState('idle');
  const [detail, setDetail] = useState('');
  const [safety, setSafety] = useState('');
  const [events, setEvents] = useState([]);

  const socketRef = useRef(null);
  const identityRef = useRef(null);
  const peerBundleRef = useRef(null);
  const activeRef = useRef(null);
  const rootKeyRef = useRef(null);
  const busyRef = useRef(false);

  const addEvent = useCallback((message) => {
    const time = new Date().toLocaleTimeString();

    setEvents((old) => [
      ...old.slice(-5),
      `${time} — ${message}`,
    ]);
  }, []);

  const fail = useCallback(
    (error) => {
      const message =
        error instanceof Error
          ? error.message
          : 'Une erreur inattendue est survenue.';

      wipeHandshakeState(activeRef.current);
      activeRef.current = null;

      if (rootKeyRef.current) {
        rootKeyRef.current.fill(0);
      }

      rootKeyRef.current = null;

      setStatus('error');
      setDetail(message);
      addEvent(`Erreur : ${message}`);
    },
    [addEvent],
  );

  const handleFrame = useCallback(
    async (frame) => {
      try {
        if (!frame || typeof frame.type !== 'string') {
          throw new Error('Trame WebSocket invalide.');
        }

        if (
          frame.type === 'PEER_OFFLINE' ||
          frame.type === 'ERROR' ||
          frame.type === 'error'
        ) {
          throw new Error(
            frame.message ||
              frame.code ||
              'Le serveur a refusé la trame.',
          );
        }

        if (
          !['hs_hello', 'hs_response', 'hs_finish'].includes(
            frame.type,
          )
        ) {
          return;
        }

        // N'accepter que les messages du contact attendu.
        if (frame.from !== peer) {
          return;
        }

        const me = identityRef.current;
        const peerBundle = peerBundleRef.current;

        if (!me || !peerBundle) {
          throw new Error(
            'Identités non initialisées. Reconnectez-vous.',
          );
        }

        // Étape 1 : le destinataire reçoit hs_hello.
        if (frame.type === 'hs_hello') {
          if (role !== 'responder') {
            addEvent(
              'hs_hello ignoré : ce client est configuré comme initiateur.',
            );
            return;
          }

          const hello = fromWire(frame, HS_FIELDS.hs_hello);

          wipeHandshakeState(activeRef.current);

          const result = responderOnHello({
            me,
            peer: { signPub: peerBundle.signPub },
            hello,
          });

          activeRef.current = {
            role: 'responder',
            state: result.state,
          };

          socketRef.current.send(
            toWire('hs_response', peer, result.wire),
          );

          setStatus('handshaking');
          setDetail('Réponse envoyée. En attente de hs_finish.');

          addEvent('hs_hello vérifié ; hs_response envoyé.');
          return;
        }

        // Étape 2 : l'initiateur reçoit hs_response.
        if (frame.type === 'hs_response') {
          const active = activeRef.current;

          if (!active || active.role !== 'initiator') {
            return;
          }

          const response = fromWire(
            frame,
            HS_FIELDS.hs_response,
          );

          const result = initiatorOnResponse({
            me,
            peer: { signPub: peerBundle.signPub },
            state: active.state,
            resp: response,
          });

          if (rootKeyRef.current) {
            rootKeyRef.current.fill(0);
          }

          rootKeyRef.current = result.root;

          // L'initiateur envoie la dernière trame du protocole.
          socketRef.current.send(
            toWire('hs_finish', peer, result.wire),
          );

          activeRef.current = null;

          setStatus('keyReady');
          setDetail(STATUS.keyReady.description);

          addEvent(
            'hs_response vérifié ; hs_finish envoyé et clé locale calculée.',
          );

          return;
        }

        // Étape 3 : le destinataire reçoit hs_finish.
        if (frame.type === 'hs_finish') {
          const active = activeRef.current;

          if (!active || active.role !== 'responder') {
            return;
          }

          const finish = fromWire(
            frame,
            HS_FIELDS.hs_finish,
          );

          const result = responderOnFinish({
            me,
            peer: { signPub: peerBundle.signPub },
            state: active.state,
            fin: finish,
          });

          if (rootKeyRef.current) {
            rootKeyRef.current.fill(0);
          }

          rootKeyRef.current = result.root;
          activeRef.current = null;

          setStatus('secure');
          setDetail(STATUS.secure.description);

          addEvent(
            'hs_finish vérifié ; clé de session calculée.',
          );
        }
      } catch (error) {
        fail(error);
      }
    },
    [addEvent, fail, peer, role],
  );

  const start = useCallback(async () => {
    if (busyRef.current) return;

    if (!currentUser || !peer || !token) {
      setStatus('error');
      setDetail(
        'Informations manquantes : currentUser, peer et token (JWT) sont requis.',
      );
      return;
    }

    if (currentUser === peer) {
      setStatus('error');
      setDetail(
        'Choisissez un autre utilisateur comme contact.',
      );
      return;
    }

    if (!['initiator', 'responder'].includes(role)) {
      setStatus('error');
      setDetail(
        'Le rôle doit être "initiator" ou "responder".',
      );
      return;
    }

    busyRef.current = true;

    setStatus('connecting');
    setDetail(
      'Chargement de l’identité locale et du bundle public du contact…',
    );
    setSafety('');
    setEvents([]);

    try {
      // Fermer une éventuelle connexion précédente.
      socketRef.current?.close();
      socketRef.current = null;

      wipeHandshakeState(activeRef.current);
      activeRef.current = null;

      if (rootKeyRef.current) {
        rootKeyRef.current.fill(0);
      }

      rootKeyRef.current = null;

      // Charger l'identité cryptographique locale.
      const me = await loadIdentity(currentUser);

      if (!me?.signPriv || !me?.signPub) {
        throw new Error(
          `Aucune identité locale pour « ${currentUser} ». Créez et enregistrez d’abord votre identité.`,
        );
      }

      // Récupérer le bundle public du contact.
      const response = await fetch(
        `${apiBase.replace(/\/$/, '')}/users/${encodeURIComponent(peer)}/keys`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        },
      );

      if (!response.ok) {
        throw new Error(
          `Impossible de récupérer le bundle du contact (HTTP ${response.status}).`,
        );
      }

      const bundle = normalizeBundle(await response.json());

      identityRef.current = me;
      peerBundleRef.current = bundle;

      setSafety(
        safetyNumber(me.signPub, bundle.signPub),
      );

      // Ouvrir le WebSocket.
      const client = connect(
        token,
        (frame) => {
          void handleFrame(frame);
        },
        socketUrl,
      );

      socketRef.current = client;

      // Attendre que le WebSocket soit ouvert.
      await new Promise((resolve, reject) => {
        const ws = client.ws;

        if (ws.readyState === WebSocket.OPEN) {
          resolve();
          return;
        }

        const cleanup = () => {
          ws.removeEventListener('open', onOpen);
          ws.removeEventListener('error', onError);
          ws.removeEventListener('close', onClose);
        };

        const onOpen = () => {
          cleanup();
          resolve();
        };

        const onError = () => {
          cleanup();
          reject(
            new Error('Connexion WebSocket impossible.'),
          );
        };

        const onClose = () => {
          cleanup();
          reject(
            new Error(
              'WebSocket fermé avant la connexion.',
            ),
          );
        };

        ws.addEventListener('open', onOpen, { once: true });
        ws.addEventListener('error', onError, { once: true });
        ws.addEventListener('close', onClose, { once: true });
      });

      if (role === 'responder') {
        setStatus('handshaking');
        setDetail(
          'Connecté. En attente du hs_hello envoyé par le contact initiateur.',
        );

        addEvent(
          'Connexion WebSocket ouverte ; en attente de hs_hello.',
        );
      } else {
        // Lancer le handshake côté initiateur.
        const hello = initiatorHello({
          me,
          peer: { signPub: bundle.signPub },
        });

        activeRef.current = {
          role: 'initiator',
          state: hello.state,
        };

        client.send(
          toWire('hs_hello', peer, hello.wire),
        );

        setStatus('handshaking');
        setDetail(
          'hs_hello envoyé. En attente de la réponse du contact.',
        );

        addEvent(
          'Connexion WebSocket ouverte ; hs_hello envoyé.',
        );
      }
    } catch (error) {
      fail(error);
    } finally {
      busyRef.current = false;
    }
  }, [
    addEvent,
    apiBase,
    currentUser,
    fail,
    handleFrame,
    peer,
    role,
    socketUrl,
    token,
  ]);

  const disconnect = useCallback(() => {
    socketRef.current?.close();
    socketRef.current = null;

    wipeHandshakeState(activeRef.current);
    activeRef.current = null;

    if (rootKeyRef.current) {
      rootKeyRef.current.fill(0);
    }

    rootKeyRef.current = null;
    identityRef.current = null;
    peerBundleRef.current = null;

    setStatus('idle');
    setDetail(
      'Connexion fermée. Aucune clé de session conservée par ce composant.',
    );
    setSafety('');

    addEvent(
      'Connexion fermée et secrets temporaires effacés au mieux.',
    );
  }, [addEvent]);

  useEffect(() => {
    return () => {
      socketRef.current?.close();

      wipeHandshakeState(activeRef.current);
      activeRef.current = null;

      if (rootKeyRef.current) {
        rootKeyRef.current.fill(0);
      }

      rootKeyRef.current = null;
      identityRef.current = null;
      peerBundleRef.current = null;
    };
  }, []);

  const currentStatus = STATUS[status] ?? STATUS.idle;

  return (
    <main style={styles.page}>
      <section
        style={styles.card}
        aria-labelledby="chat-title"
      >
        <header style={styles.header}>
          <div>
            <p style={styles.eyebrow}>
              MESSAGERIE SÉCURISÉE · PROTOTYPE
            </p>

            <h1 id="chat-title" style={styles.title}>
              Conversation
            </h1>

            <p style={styles.subtitle}>
              Connecté en tant que{' '}
              <strong>{currentUser || '—'}</strong>
            </p>
          </div>

          <div
            style={{
              ...styles.statusPill,
              color: currentStatus.color,
              borderColor: currentStatus.color,
            }}
            role="status"
          >
            <span aria-hidden="true">●</span>{' '}
            {currentStatus.title}
          </div>
        </header>

        <div style={styles.contact}>
          <div style={styles.avatar} aria-hidden="true">
            {(peer || '?').slice(0, 1).toUpperCase()}
          </div>

          <div style={{ flex: 1, minWidth: 0 }}>
            <h2 style={styles.contactName}>
              {peer || 'Aucun contact sélectionné'}
            </h2>

            <p style={styles.muted}>
              Handshake hybride · Ed25519 + X25519 + ML-KEM-768
            </p>
          </div>
        </div>

        <section
          style={styles.securityBox}
          aria-live="polite"
        >
          <h2 style={styles.sectionTitle}>
            État de sécurité
          </h2>

          <p
            style={{
              ...styles.statusText,
              color: currentStatus.color,
            }}
          >
            {currentStatus.title}
          </p>

          <p style={styles.bodyText}>
            {detail || currentStatus.description}
          </p>

          {safety && (
            <div style={styles.fingerprint}>
              <p style={styles.fingerprintLabel}>
                Numéro de sécurité — comparez-le avec votre
                contact par un autre canal
              </p>

              <code style={styles.fingerprintValue}>
                {safety}
              </code>
            </div>
          )}
        </section>

        <div style={styles.actions}>
          <button
            type="button"
            style={styles.primaryButton}
            onClick={start}
            disabled={
              busyRef.current ||
              status === 'connecting' ||
              status === 'handshaking'
            }
          >
            Démarrer / recommencer le handshake
          </button>

          <button
            type="button"
            style={styles.secondaryButton}
            onClick={disconnect}
          >
            Déconnecter
          </button>
        </div>

        <section style={styles.messages}>
          <h2 style={styles.sectionTitle}>
            Journal des événements
          </h2>

          {events.length === 0 ? (
            <p style={styles.muted}>
              Aucun événement pour le moment.
            </p>
          ) : (
            <ul style={styles.eventList}>
              {events.map((event, index) => (
                <li
                  style={styles.event}
                  key={`${index}-${event}`}
                >
                  {event}
                </li>
              ))}
            </ul>
          )}
        </section>

        <aside style={styles.notice}>
          <strong>Limite actuelle :</strong> ce composant
          met en place le handshake et affiche son état.
          L’envoi de messages de chat n’est pas activé, car
          le client ne contient pas encore de protocole de
          chiffrement et de déchiffrement des messages ni
          de serveur relais. Le serveur doit également
          respecter les formats des réponses HTTP et des
          trames WebSocket attendus par le client.
        </aside>
      </section>
    </main>
  );
}

const styles = {
  page: {
    minHeight: '100vh',
    boxSizing: 'border-box',
    padding: '32px 16px',
    background: '#f4f6f8',
    color: '#17212f',
    fontFamily:
      'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
  },

  card: {
    width: '100%',
    maxWidth: 760,
    margin: '0 auto',
    background: '#fff',
    border: '1px solid #e0e5eb',
    borderRadius: 14,
    padding: 24,
    boxSizing: 'border-box',
    boxShadow: '0 8px 24px rgba(20, 35, 55, 0.05)',
  },

  header: {
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: 16,
    paddingBottom: 22,
    borderBottom: '1px solid #e8edf2',
  },

  eyebrow: {
    margin: '0 0 6px',
    fontSize: 11,
    letterSpacing: '1.2px',
    fontWeight: 700,
    color: '#66758a',
  },

  title: {
    margin: 0,
    fontSize: 28,
    lineHeight: 1.2,
    fontWeight: 700,
    color: '#152235',
  },

  subtitle: {
    margin: '8px 0 0',
    color: '#66758a',
    fontSize: 14,
  },

  statusPill: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 7,
    border: '1px solid',
    borderRadius: 999,
    padding: '7px 10px',
    fontSize: 12,
    fontWeight: 700,
  },

  contact: {
    display: 'flex',
    alignItems: 'center',
    gap: 14,
    padding: '22px 0',
    borderBottom: '1px solid #e8edf2',
  },

  avatar: {
    width: 46,
    height: 46,
    borderRadius: '50%',
    background: '#e7edf5',
    color: '#344b67',
    display: 'grid',
    placeItems: 'center',
    fontWeight: 700,
    fontSize: 18,
    flexShrink: 0,
  },

  contactName: {
    margin: 0,
    fontSize: 17,
    fontWeight: 650,
    color: '#17212f',
  },

  muted: {
    margin: '5px 0 0',
    fontSize: 13,
    color: '#68778b',
    lineHeight: 1.5,
  },

  securityBox: {
    marginTop: 22,
    padding: 18,
    border: '1px solid #e3e8ef',
    borderRadius: 10,
    background: '#fbfcfd',
  },

  sectionTitle: {
    margin: '0 0 12px',
    fontSize: 15,
    fontWeight: 700,
    color: '#26364a',
  },

  statusText: {
    margin: 0,
    fontWeight: 700,
    fontSize: 15,
  },

  bodyText: {
    margin: '7px 0 0',
    fontSize: 13,
    lineHeight: 1.6,
    color: '#596a7f',
  },

  fingerprint: {
    marginTop: 16,
    paddingTop: 14,
    borderTop: '1px solid #e3e8ef',
  },

  fingerprintLabel: {
    margin: '0 0 8px',
    fontSize: 12,
    color: '#68778b',
    lineHeight: 1.5,
  },

  fingerprintValue: {
    display: 'block',
    overflowWrap: 'anywhere',
    fontSize: 13,
    lineHeight: 1.9,
    letterSpacing: '0.4px',
    color: '#24364b',
    background: '#eef2f6',
    padding: 10,
    borderRadius: 6,
  },

  actions: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: 10,
    marginTop: 18,
  },

  primaryButton: {
    border: '1px solid #243f60',
    borderRadius: 7,
    background: '#243f60',
    color: '#fff',
    padding: '10px 14px',
    fontSize: 13,
    fontWeight: 650,
    cursor: 'pointer',
  },

  secondaryButton: {
    border: '1px solid #cbd4df',
    borderRadius: 7,
    background: '#fff',
    color: '#34465d',
    padding: '10px 14px',
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer',
  },

  messages: {
    marginTop: 24,
  },

  eventList: {
    listStyle: 'none',
    margin: 0,
    padding: 0,
    display: 'grid',
    gap: 8,
  },

  event: {
    fontSize: 12,
    lineHeight: 1.5,
    color: '#53647a',
    background: '#f7f9fb',
    border: '1px solid #e8edf2',
    borderRadius: 6,
    padding: '9px 10px',
    overflowWrap: 'anywhere',
  },

  notice: {
    marginTop: 22,
    borderLeft: '3px solid #b7791f',
    padding: '10px 12px',
    background: '#fff9ed',
    color: '#73511d',
    fontSize: 12,
    lineHeight: 1.65,
  },
};