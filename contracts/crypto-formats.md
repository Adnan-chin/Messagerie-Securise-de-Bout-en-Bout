# Formats cryptographiques (contrat v1)

## 1. Encodage
- Toutes les données binaires (clés, signatures, nonces, ciphertexts) circulent en
  base64 standard avec remplissage (`=`) dans du JSON.
- Les tailles ci-dessous sont celles des octets APRÈS décodage.
- Le serveur rejette toute valeur de mauvaise taille (erreur INVALID_SIZE).
- sid = UUID v4, représenté dans les messages signés par ses 16 octets.
- Entiers (epoch, counter) : 4 octets, grand-boutiste (big-endian).

## 2. Tailles fixes
| Donnée                              | Octets      |
|-------------------------------------|-------------|
| Ed25519 clé publique / signature    | 32 / 64     |
| X25519 clé publique                 | 32          |
| ML-KEM-768 ek (encapsulation) / ct  | 1184 / 1088 |
| Nonce d'authentification            | 32          |
| Nonce XChaCha20 / tag Poly1305      | 24 / 16     |
| sid                                 | 16          |

## 3. Messages signés (étiquette de domaine + champs de longueur fixe)
idA, idB = clés publiques Ed25519 d'Alice et de Bob.

    auth   = "auth-v1" || nonce(32) || username
    hs-1   = "hs-1" || sid || idA || idB || eA_pub
    hs-2   = "hs-2" || sid || idA || idB || eA_pub || eB_pub || ekB
    hs-3   = "hs-3" || sid || idA || idB || eA_pub || eB_pub || ekB || ct
    rk-n   = "rk-n" || sid || epoch(4) || idA || idB || (éléments de l'étape)
    transcript (salage HKDF) = sid || idA || idB || eA_pub || eB_pub || ekB || ct

## 4. HKDF-SHA-256 : étiquettes `info`
- secure-messenger/v1/root
- secure-messenger/v1/rekey
- secure-messenger/v1/chain-A->B
- secure-messenger/v1/chain-B->A
- secure-messenger/v1/msg
- secure-messenger/v1/next
Toute nouvelle étiquette passe par une PR sur ce fichier.

## 5. AAD d'un message (AEAD)
    sid(16) || epoch(4, BE) || counter(4, BE) || rekey(1 : 0 ou 1)
Format binaire fixe : un JSON réordonné ne doit jamais casser le déchiffrement.

## 6. Versions des librairies
@noble/curves 2.4.0, @noble/post-quantum 0.7.1, @noble/hashes 2.4.0,
libsodium-wrappers-sumo 0.8.4 (versions exactes, celles du package-lock).