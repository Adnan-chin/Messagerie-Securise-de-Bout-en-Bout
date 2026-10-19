FROM node:22-alpine

# Définition du répertoire de travail
WORKDIR /usr/src/app

# Copie uniquement des fichiers de dépendances
COPY package*.json ./

# Installation propre des dépendances
RUN npm ci

# Copie du reste du code source
COPY . .

# Exposition du port
EXPOSE 4040

# Commande de lancement (adapter selon votre package.json)
CMD ["node", "index.js"]