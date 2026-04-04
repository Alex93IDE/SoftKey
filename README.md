# Softkey

I got tired of depending on my phone for 2FA. So I built this — a tiny self-hosted TOTP authenticator that runs in your browser, on your own machine, with no phone, no cloud, and no account required.

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

## A few things worth knowing

- Everything is encrypted with AES-256-GCM. Secrets never leave your machine.
- The app locks itself when you close the tab, and auto-locks after inactivity.
- Export/import works with any app that supports `otpauth://` URIs (Google Authenticator, Aegis, Proton Pass, Authy...).

## If this is useful to you

- Star the repo
- Open an issue if something breaks or you want a feature
- [Sponsor development](https://github.com/sponsors/Alex93IDE)
