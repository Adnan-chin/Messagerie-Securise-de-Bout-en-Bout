=======
# Messagerie sécurisée de bout en bout
Messagerie web chiffrée de bout en bout : échange de clés hybride X25519 + ML-KEM-768, forward secrecy, ratchet par message et rotation des clés.
Projet du cours Cryptographie Elliptique (Master Cryptographie et Sécurité de l'Information).

## Principe
Le serveur n'est qu'un annuaire de clés publiques et un relais de messages chiffrés.
Toute la cryptographie s'exécute dans le navigateur. 
Le serveur ne voit jamais de clé privée, de clé de session ni de texte clair.

## Structure- 
`client/`    - application React + module "src/crypto/" (équipe client)
`server/`    - API Express, WebSocket, PostgreSQL (équipe Serveur)

`contracts/` - formats d'API, de messages et de cryptographie (partagé)- 
`tests/`     - tests unitaires, d'intégration et de sécurité- 
`docs/`      - rapport, schémas, mesures

## Prérequis
Node.js 22 LTS, Docker et Docker Compose, Git.

## Lancement
```
docker compose up -d            # base de données + serveur
cd client && npm install && npm run dev
```
Vérification : http://localhost:3000/health doit répondre 
{"status":"ok","db":true}.

## Tests
```
npm test         # depuis la racine               
```



