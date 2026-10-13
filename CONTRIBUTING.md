# Contributing
Issues and pull requests are welcome.
- UI lives in `ui/index.html` (plain HTML/CSS/JS, no build step). Backend is Rust in `src-tauri/src/main.rs`.
- Run with `cargo tauri dev`. Keep the app light: avoid new heavy dependencies and expensive CSS effects.
- Add translations in the `T` object (fa / en) in `ui/index.html`.
