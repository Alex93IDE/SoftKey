# Softkey

A self-hosted TOTP authenticator that runs in your browser. No phone, no cloud, no account required — your 2FA codes live on your own machine, encrypted, and accessible from any tab.

<table>
  <tr>
    <td align="center"><img src="docs/screen-login.png" width="200"/><br/><sub>Login</sub></td>
    <td align="center"><img src="docs/screen-setup.png" width="200"/><br/><sub>First-time setup</sub></td>
    <td align="center"><img src="docs/screen-recovery.png" width="200"/><br/><sub>Recovery code</sub></td>
  </tr>
  <tr>
    <td align="center"><img src="docs/screen-main.png" width="200"/><br/><sub>Token list</sub></td>
    <td align="center"><img src="docs/screen-add.png" width="200"/><br/><sub>Add token</sub></td>
    <td align="center"><img src="docs/screen-settings.png" width="200"/><br/><sub>Settings / Auto-lock</sub></td>
  </tr>
</table>

## Setup

### Docker

```bash
docker compose up -d
```

### Without Docker

```bash
npm install
node main.js
```

Open [http://localhost:3333](http://localhost:3333). On first launch you'll create a master password — **save the recovery code**, it's the only way back in if you forget it.

## How it works

Your TOTP secrets are encrypted with AES-256-GCM using a key derived from your master password. The encrypted file stays on disk; the decryption key lives in memory only — it's never written anywhere. Close the tab and the vault locks itself. There's also a configurable inactivity timeout.

No telemetry, no network calls, no sync service. If you want to verify that, the codebase is small enough to read in an hour.

## Import / Export

Softkey uses standard `otpauth://totp/` URIs, the same format as Google Authenticator, Aegis, Proton Pass, and Authy. You can migrate in or out at any time without friction.


## If this is useful to you

- Star the repo
- Open an issue if something breaks or you want a feature
- [Sponsor development](https://github.com/sponsors/Alex93IDE)
