# Softkey

A minimal, self-hosted personal 2FA authenticator that runs locally in your browser. No cloud, no accounts, no phone required.

## Features

- Generate TOTP codes (RFC 6238) for any service
- Visual countdown ring per token
- Click any code to copy it to clipboard
- Export your token list as JSON
- Runs entirely on your machine — secrets never leave it

## Requirements

- Node.js 18+

## Setup

```bash
npm install
node main.js
```

Then open [http://localhost:3333](http://localhost:3333) in your browser.

## Adding a token

1. Click **+ Add** at the bottom
2. Enter a name (e.g. `GitHub`) and your TOTP secret
3. Click **Add** — the code appears immediately

Secrets are stored in `secrets.json` in the project root. This file is excluded from git.

## Project structure

```
main.js           Express server + REST API
index.html        Frontend (single file, no build step)
secrets.json      Your TOTP secrets (git-ignored)
secrets.example.json  Example format for secrets.json
```

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/tokens` | Returns all tokens with current codes and time remaining |
| POST | `/api/secrets` | Add a new secret `{ name, secret }` |
| DELETE | `/api/secrets/:id` | Remove a secret by id |
