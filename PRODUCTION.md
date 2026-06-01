# Déploiement Netlify AD Hedomey

Le projet est maintenant compatible Netlify. Le site reste statique côté pages HTML, et le backend passe par des Netlify Functions avec stockage persistant Netlify Blobs.

## 1. Préparer le compte Netlify

Dans Netlify, créez un nouveau site depuis votre dépôt Git ou en important le dossier du projet.

Netlify utilisera automatiquement :

- `netlify.toml` pour les routes et redirects.
- `npm run build` pour générer le dossier public `dist`.
- `netlify/functions/api.js` pour les routes `/api/...`.
- `netlify/functions/media.js` pour les images et audios envoyés depuis l'admin.

Le dossier publié est `dist`, pas la racine du projet. Les fichiers backend, `package.json` et la documentation ne sont donc pas exposés comme fichiers statiques.

## 2. Variables d'environnement obligatoires

Dans Netlify : `Site configuration` > `Environment variables`, ajoutez :

```bash
ADMIN_USERNAME=votre_admin
ADMIN_PASSWORD_HASH=scrypt$...
SESSION_SECRET=une_cle_tres_longue_et_secrete_32_caracteres_minimum
NODE_ENV=production
```

Générez le hash du mot de passe en local :

```bash
npm run hash-password -- "VotreMotDePasseTresFort"
```

Copiez la valeur générée dans `ADMIN_PASSWORD_HASH`.

Important : ne gardez pas `admin / admin123` en production.

## 3. Commandes Netlify

Pour tester localement avec Netlify Functions :

```bash
npm install
npm run netlify:dev
```

Pour vérifier la syntaxe :

```bash
npm run check
npm run check:functions
```

Pour vérifier le build Netlify localement :

```bash
npm run build
```

## 4. URLs du site

- Accueil : `/`
- Prédications : `/predications`
- À propos : `/apropos`
- Contact : `/contact`
- Admin : `/admin`
- Connexion admin : `/admin/login`
- Santé backend : `/api/health`

## 5. Données et fichiers

Sur Netlify, les données ne sont pas écrites dans `backend/data`. Elles sont stockées dans Netlify Blobs :

- messages contact
- inscriptions newsletter
- prédications publiées
- images envoyées
- audios envoyés

Les URLs publiques des médias restent sous la forme :

- `/uploads/images/...`
- `/uploads/audio/...`

## 6. Sécurité incluse

- Connexion admin avec nom d'utilisateur et mot de passe.
- Mot de passe hashé via `ADMIN_PASSWORD_HASH`.
- Session admin signée avec `SESSION_SECRET`.
- Cookies `HttpOnly`, `SameSite=Lax`, `Secure` en production.
- Limitation des tentatives de connexion.
- Validation des formulaires contact, newsletter et prédications.
- Validation des formats image/audio.
- Limite de taille d'upload via `MAX_BODY_SIZE`.
- Headers de sécurité HTTP.

## 7. Variables optionnelles

```bash
SESSION_TTL_MS=28800000
MAX_BODY_SIZE=52428800
LOGIN_WINDOW_MS=900000
LOGIN_MAX_ATTEMPTS=5
```

## 8. Ancien serveur Node

Le fichier `backend/server.js` reste utile pour tester en local avec `npm start`. Sur Netlify, le backend utilisé est celui des Functions dans `netlify/functions/`.
