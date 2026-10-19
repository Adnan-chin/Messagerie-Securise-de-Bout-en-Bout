// Stockage local des cles privees dans IndexedDB. Aucun appel reseau.
// Limite connue : IndexedDB n'est pas chiffre (voir bonus : chiffrement au repos).
const DB_NAME = 'secure-messenger';
const STORE = 'identity';

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function run(mode, fn) {
  return openDb().then((db) => new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, mode);
    const req = fn(tx.objectStore(STORE));
    tx.oncomplete = () => { db.close(); resolve(req.result); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  }));
}

export const saveIdentity = (username, identity) => run('readwrite', (s) => s.put(identity, username));
export const loadIdentity = (username) => run('readonly', (s) => s.get(username));
export const deleteIdentity = (username) => run('readwrite', (s) => s.delete(username));