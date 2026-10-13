<div align="center">
  <img src="ui/icon/logo.webp" alt="API Vault logo" width="104" height="104" />
  <h1>API Vault</h1>
  <p><strong>A private, encrypted vault for AI API credentials — with a built-in multi-provider chat.</strong></p>
  <p>
    <a href="README.fa.md">فارسی</a> ·
    <a href="../../releases">Releases</a> ·
    <a href="../../issues">Report a bug</a>
  </p>
  <p>
    <img alt="Built with Rust" src="https://img.shields.io/badge/Built%20with-Rust-orange?logo=rust&logoColor=white" />
    <img alt="Tauri 2" src="https://img.shields.io/badge/Tauri-2-24C8DB?logo=tauri&logoColor=white" />
    <img alt="Platforms Windows and Linux" src="https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20macOS-4C8BF5" />
    <img alt="Languages Persian and English" src="https://img.shields.io/badge/Language-English%20%7C%20Persian-7952B3" />
    <img alt="MIT License" src="https://img.shields.io/badge/License-MIT-green.svg" />
  </p>
</div>

---

## Overview

**API Vault** is a lightweight desktop app for saving AI API configurations and chatting with your chosen models from one place. It is built with **Rust + Tauri 2**, with a web-based interface, and supports **English and Persian (RTL)**.

Your saved API configurations and chat history are kept in a local encrypted vault. When you test a connection or send a chat message, the relevant request is sent to the API endpoint configured for that provider.

## Features

- **Encrypted local vault** — the vault is encrypted with **ChaCha20-Poly1305**; a key derived from your PIN or password using **Argon2id** is used to protect it.
- **Flexible locking** — choose a PIN, password, or no-lock mode; configure an idle timeout and optionally lock the app when it is hidden.
- **Multiple providers** — presets for OpenAI, Google Gemini, Anthropic, OpenRouter, Groq and Mistral, plus custom OpenAI-compatible endpoints.
- **API management** — edit provider, display name, model, endpoint, key and notes; reveal or mask keys, copy values, mark favorites, and test one or all saved connections.
- **Built-in AI chat** — use a saved API to chat with a model, attach images or supported text/code files, and keep a searchable conversation history.
- **Chat tools** — pin, rename or delete conversations; render Markdown, links and code blocks, with copy actions where available.
- **Export** — print/export saved API details to PDF, with a masked-key option and an extra confirmation before exporting full keys when a lock is enabled.
- **Customizable interface** — liquid-glass effects with performance levels, solid or glass chat presentation, light/dark/system themes, custom background, and English/Persian UI.
- **Desktop conveniences** — system-tray behavior, single-instance support, and optional clipboard clearing 30 seconds after copying an API key.

## Download

Get the latest published packages from **[GitHub Releases](../../releases)**.

| Platform | Package | Notes |
| --- | --- | --- |
| Windows | `API Vault_*_x64-setup.exe` | Installer |
| Windows | `API-Vault-portable.exe` | Portable executable; no installer needed |
| Linux | `.deb` | Debian/Ubuntu package |
| Linux | `.AppImage` | Make executable with `chmod +x <file>` before running |
| macOS | `API-Vault-macos-arm64.dmg` | Apple Silicon Macs (M-series) |
| macOS | `API-Vault-macos-x64.dmg` | Intel Macs |

Windows may show a Microsoft Defender SmartScreen warning because the executable is not code-signed. The macOS packages are also not signed or notarized with an Apple Developer ID, so macOS may show a security warning. Only run software you trust and have obtained from the project's official release page.

> **No release yet?** The workflow can also be started manually from the repository's **Actions** tab. A manual run uploads build artifacts; pushing a version tag (`v*`) also publishes a GitHub Release.

## Build from source

### Requirements

- [Rust toolchain](https://rustup.rs/)
- Tauri CLI v2:
  ```bash
  cargo install tauri-cli --version "^2" --locked
  ```
- **Windows:** Visual Studio Build Tools with **Desktop development with C++**. WebView2 is normally available on Windows 10/11.
- **Linux (Debian/Ubuntu):**
  ```bash
  sudo apt-get update
  sudo apt-get install -y build-essential curl wget file libssl-dev libxdo-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev
  ```

### Run in development

```bash
# Clone your repository (replace YOUR_GITHUB_USERNAME with your GitHub username)
git clone https://github.com/YOUR_GITHUB_USERNAME/api-vault.git
cd api-vault

cargo tauri dev
```

### Build a release

```bash
# Windows installer
cargo tauri build --bundles nsis

# Linux packages (run on a supported Linux build environment)
cargo tauri build --bundles deb,appimage

# macOS disk image (run on macOS)
cargo tauri build --bundles dmg
```

Build output is written under `src-tauri/target/release/`. Bundled installers/packages are located in `src-tauri/target/release/bundle/`.

## Project structure

```text
api-vault/
├── .github/workflows/release.yml  # CI build and release workflow
├── src-tauri/
│   ├── src/main.rs                # Rust backend, vault and API requests
│   └── tauri.conf.json            # App identity and Tauri configuration
├── ui/
│   ├── index.html                 # HTML, CSS and JavaScript interface
│   ├── fonts/                     # Optional local fonts
│   ├── ico/                       # Provider icons
│   ├── icon/                      # App logo and icons
│   └── png/                       # Default background image
├── README.md                      # English documentation
└── README.fa.md                   # Persian documentation
```

## Data storage and security notes

- **Windows:** `%APPDATA%\com.apivault.app\vault.bin`
- **Linux:** `~/.local/share/com.apivault.app/vault.bin`
- Chat history is stored inside the same encrypted vault.
- With **No lock** selected, the random encryption key is stored alongside the vault in `vault.key`. This mode is for convenience and does **not** provide meaningful protection against someone who can access your user account and files.
- If you forget your PIN or password, the encrypted data cannot be recovered through the app. Keep a secure record of your credential.
- When you use chat or connection testing, your API key and/or message content is sent to the provider endpoint you configured. The provider's privacy and retention policies apply to those requests.

For security reports, please follow [SECURITY.md](SECURITY.md) rather than posting sensitive details in a public issue.

## Customization

- Default background: `ui/png/web.webp`
- Provider icons: `ui/ico/`
- App logo and icons: `ui/icon/`
- Optional Persian font: see `ui/fonts/README.txt`
- To update the repository link shown in **Settings → About**, edit the `APP.repo` value near the top of `ui/index.html`.

## Contributing

Bug reports and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) before making changes.

## Roadmap

Potential future improvements include encrypted backup/restore, streaming responses, additional provider integrations, and signed/notarized distribution packages.

## License

Released under the [MIT License](LICENSE). Copyright © 2026 Armin Barani.
