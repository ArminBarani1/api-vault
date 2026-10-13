#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fs, path::PathBuf, sync::{atomic::{AtomicBool, Ordering}, Mutex, OnceLock}, time::{Duration, SystemTime, UNIX_EPOCH}};
use tauri::{menu::{Menu, MenuItem}, tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent}, AppHandle, Emitter, Manager, State};

static TRAY: AtomicBool = AtomicBool::new(true);
static HTTP: OnceLock<reqwest::Client> = OnceLock::new();
fn http() -> &'static reqwest::Client {
    HTTP.get_or_init(|| reqwest::Client::builder().build().expect("http client"))
}

#[derive(Serialize, Deserialize)]
struct VaultFile { mode: String, salt: String, nonce: String, data: String }
struct Session { key: [u8; 32], salt: Vec<u8>, mode: String }
struct App { path: PathBuf, sess: Mutex<Option<Session>> }

fn kp(p: &PathBuf) -> PathBuf { p.with_extension("key") }
#[cfg(unix)]
fn lock_down(p: &PathBuf) { use std::os::unix::fs::PermissionsExt; let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o600)); }
#[cfg(not(unix))]
fn lock_down(_p: &PathBuf) {}

fn derive(secret: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut k = [0u8; 32];
    Argon2::default().hash_password_into(secret.as_bytes(), salt, &mut k).map_err(|e| e.to_string())?;
    Ok(k)
}
fn write_vault(path: &PathBuf, key: &[u8; 32], salt: &[u8], mode: &str, plain: &str) -> Result<(), String> {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = ChaCha20Poly1305::new(key.into())
        .encrypt(Nonce::from_slice(&nonce), plain.as_bytes()).map_err(|e| e.to_string())?;
    let f = VaultFile { mode: mode.into(), salt: B64.encode(salt), nonce: B64.encode(nonce), data: B64.encode(ct) };
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec(&f).unwrap()).map_err(|e| e.to_string())?;
    lock_down(&tmp);
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}
fn read_vault(path: &PathBuf) -> Option<VaultFile> { serde_json::from_slice(&fs::read(path).ok()?).ok() }
fn open_key(f: &VaultFile, key: &[u8; 32]) -> Result<String, String> {
    let nonce = B64.decode(&f.nonce).map_err(|_| "bad")?;
    let ct = B64.decode(&f.data).map_err(|_| "bad")?;
    let pt = ChaCha20Poly1305::new(key.into())
        .decrypt(Nonce::from_slice(&nonce), ct.as_ref()).map_err(|_| "wrong".to_string())?;
    String::from_utf8(pt).map_err(|_| "bad".to_string())
}
fn open(f: &VaultFile, secret: &str) -> Result<([u8; 32], Vec<u8>, String), String> {
    let salt = B64.decode(&f.salt).map_err(|_| "bad")?;
    let key = derive(secret, &salt)?;
    let plain = open_key(f, &key)?;
    Ok((key, salt, plain))
}
fn nokey(path: &PathBuf) -> Result<[u8; 32], String> {
    let s = fs::read_to_string(kp(path)).map_err(|e| e.to_string())?;
    let kb = B64.decode(s.trim()).map_err(|_| "bad")?;
    let key: [u8; 32] = kb.try_into().map_err(|_| "bad")?;
    Ok(key)
}
// "none" = random key kept in vault.key; otherwise the key is derived from the secret (Argon2id)
fn gen_keys(secret: &str, mode: &str) -> Result<([u8; 32], Vec<u8>), String> {
    if mode == "none" {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        Ok((k, vec![]))
    } else {
        let mut salt = vec![0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Ok((derive(secret, &salt)?, salt))
    }
}
// order matters so a crash never leaves a vault without its key
fn commit(path: &PathBuf, key: &[u8; 32], salt: &[u8], mode: &str, plain: &str) -> Result<(), String> {
    if mode == "none" {
        fs::write(kp(path), B64.encode(key)).map_err(|e| e.to_string())?;
        lock_down(&kp(path));
        write_vault(path, key, salt, mode, plain)
    } else {
        write_vault(path, key, salt, mode, plain)?;
        let _ = fs::remove_file(kp(path));
        Ok(())
    }
}

#[tauri::command]
fn status(s: State<App>) -> Value {
    match read_vault(&s.path) { Some(f) => json!({"exists": true, "mode": f.mode}), None => json!({"exists": false}) }
}
#[tauri::command]
fn setup(s: State<App>, secret: String, mode: String) -> Result<(), String> {
    if s.path.exists() {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let _ = fs::rename(&s.path, s.path.with_extension(format!("bak{}", ts)));
    }
    let (key, salt) = gen_keys(&secret, &mode)?;
    commit(&s.path, &key, &salt, &mode, "{\"items\":[],\"chats\":[]}")?;
    *s.sess.lock().unwrap() = Some(Session { key, salt, mode });
    Ok(())
}
#[tauri::command]
fn unlock(s: State<App>, secret: String) -> Result<String, String> {
    let f = read_vault(&s.path).ok_or("novault")?;
    let (key, salt, plain) = open(&f, &secret)?;
    *s.sess.lock().unwrap() = Some(Session { key, salt, mode: f.mode });
    Ok(plain)
}
#[tauri::command]
fn unlock_none(s: State<App>) -> Result<String, String> {
    let f = read_vault(&s.path).ok_or("novault")?;
    if f.mode != "none" { return Err("locked".into()); }
    let key = nokey(&s.path)?;
    let plain = open_key(&f, &key)?;
    *s.sess.lock().unwrap() = Some(Session { key, salt: vec![], mode: "none".into() });
    Ok(plain)
}
#[tauri::command]
fn lock(s: State<App>) { *s.sess.lock().unwrap() = None; }
#[tauri::command]
fn reset_vault(s: State<App>) {
    let _ = fs::remove_file(&s.path);
    let _ = fs::remove_file(kp(&s.path));
    *s.sess.lock().unwrap() = None;
}
#[tauri::command]
fn save(s: State<App>, data: String) -> Result<(), String> {
    let g = s.sess.lock().unwrap();
    let se = g.as_ref().ok_or("locked")?;
    write_vault(&s.path, &se.key, &se.salt, &se.mode, &data)
}
#[tauri::command]
fn set_lock(s: State<App>, old: String, neu: String, mode: String) -> Result<(), String> {
    let f = read_vault(&s.path).ok_or("novault")?;
    let plain = if f.mode == "none" { open_key(&f, &nokey(&s.path)?)? } else { open(&f, &old)?.2 };
    let (key, salt) = gen_keys(&neu, &mode)?;
    commit(&s.path, &key, &salt, &mode, &plain)?;
    *s.sess.lock().unwrap() = Some(Session { key, salt, mode });
    Ok(())
}
#[tauri::command]
fn set_tray(on: bool) { TRAY.store(on, Ordering::Relaxed); }

#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) { return Err("bad url".into()); }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("rundll32").arg("url.dll,FileProtocolHandler").arg(&url)
            .creation_flags(0x0800_0000).spawn().map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "linux")]
    { std::process::Command::new("xdg-open").arg(&url).spawn().map_err(|e| e.to_string())?; }
    #[cfg(target_os = "macos")]
    { std::process::Command::new("open").arg(&url).spawn().map_err(|e| e.to_string())?; }
    Ok(())
}

#[tauri::command]
async fn test_connection(url: String, key: String) -> Result<String, String> {
    let c = http();
    let u = url.trim();
    let req = if u.contains("generativelanguage.googleapis.com") {
        c.get("https://generativelanguage.googleapis.com/v1beta/models").header("x-goog-api-key", &key)
    } else {
        let base = u.split("/chat/completions").next().unwrap().split("/messages").next().unwrap().trim_end_matches('/');
        let r = c.get(format!("{}/models", base));
        if u.contains("anthropic.com") { r.header("x-api-key", &key).header("anthropic-version", "2023-06-01") } else { r.bearer_auth(&key) }
    };
    let res = req.timeout(Duration::from_secs(15)).send().await.map_err(|e| e.without_url().to_string())?;
    Ok(res.status().as_u16().to_string())
}

#[derive(Deserialize)]
struct Img { mime: String, data: String }
#[derive(Deserialize)]
struct Msg { role: String, text: String, #[serde(default)] imgs: Vec<Img> }

fn join_text(a: &Vec<Value>, key: &str) -> String {
    a.iter().filter_map(|p| p[key].as_str()).collect::<Vec<_>>().join("")
}

#[tauri::command]
async fn chat(url: String, key: String, model: String, msgs: Vec<Msg>) -> Result<String, String> {
    let c = http();
    let u = url.trim().to_string();
    let (req, kind) = if u.contains("generativelanguage.googleapis.com") {
        let contents: Vec<Value> = msgs.iter().map(|m| {
            let mut parts = vec![json!({"text": m.text})];
            for i in &m.imgs { parts.push(json!({"inline_data": {"mime_type": i.mime, "data": i.data}})); }
            json!({"role": if m.role == "assistant" { "model" } else { "user" }, "parts": parts})
        }).collect();
        let name = model.trim().trim_start_matches("models/");
        (c.post(format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent", name))
            .header("x-goog-api-key", &key).body(json!({"contents": contents}).to_string()), 0)
    } else if u.contains("anthropic.com") {
        let ms: Vec<Value> = msgs.iter().map(|m| {
            let mut parts: Vec<Value> = vec![];
            for i in &m.imgs { parts.push(json!({"type": "image", "source": {"type": "base64", "media_type": i.mime, "data": i.data}})); }
            parts.push(json!({"type": "text", "text": m.text}));
            json!({"role": m.role, "content": parts})
        }).collect();
        (c.post(&u).header("x-api-key", &key).header("anthropic-version", "2023-06-01")
            .body(json!({"model": model, "max_tokens": 4096, "messages": ms}).to_string()), 1)
    } else {
        let ep = if u.ends_with("/chat/completions") { u.clone() } else { format!("{}/chat/completions", u.trim_end_matches('/')) };
        let ms: Vec<Value> = msgs.iter().map(|m| {
            if m.imgs.is_empty() { return json!({"role": m.role, "content": m.text}); }
            let mut parts = vec![json!({"type": "text", "text": m.text})];
            for i in &m.imgs { parts.push(json!({"type": "image_url", "image_url": {"url": format!("data:{};base64,{}", i.mime, i.data)}})); }
            json!({"role": m.role, "content": parts})
        }).collect();
        (c.post(ep).bearer_auth(&key).body(json!({"model": model, "messages": ms}).to_string()), 2)
    };
    let res = req.header("content-type", "application/json").timeout(Duration::from_secs(180))
        .send().await.map_err(|e| e.without_url().to_string())?;
    let st = res.status();
    let txt = res.text().await.map_err(|e| e.without_url().to_string())?;
    if !st.is_success() {
        return Err(format!("HTTP {}: {}", st.as_u16(), txt.chars().take(500).collect::<String>()));
    }
    let v: Value = serde_json::from_str(&txt).map_err(|e| e.to_string())?;
    let out: Option<String> = match kind {
        0 => v["candidates"][0]["content"]["parts"].as_array().map(|a| join_text(a, "text")),
        1 => v["content"].as_array().map(|a| join_text(a, "text")),
        _ => match &v["choices"][0]["message"]["content"] {
            Value::String(s) => Some(s.clone()),
            Value::Array(a) => Some(join_text(a, "text")),
            _ => None,
        },
    };
    out.filter(|s| !s.is_empty()).ok_or_else(|| format!("Unexpected response: {}", txt.chars().take(300).collect::<String>()))
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| { show_main(app); }))
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            fs::create_dir_all(&dir)?;
            app.manage(App { path: dir.join("vault.bin"), sess: Mutex::new(None) });
            let show = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("API Vault")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => show_main(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if TRAY.load(Ordering::Relaxed) {
                    api.prevent_close();
                    let _ = window.hide();
                    let _ = window.emit("hidden", ());
                }
            }
        })
        .invoke_handler(tauri::generate_handler![status, setup, unlock, unlock_none, lock, reset_vault, save, set_lock, set_tray, open_url, test_connection, chat])
        .run(tauri::generate_context!())
        .expect("error while running API Vault");
}
