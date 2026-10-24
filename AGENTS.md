# AGENTS.md

## Environment

- All commands must run inside `nix-shell` (provides LuaJIT, LuaSocket, lua-cjson, OpenSSL; sets `LD_LIBRARY_PATH` so LuaJIT FFI can find `libcrypto`). Outside it, `src/crypto.lua` fails at `ffi.load("crypto")`.
- POSIX-only: the client's live-receive uses FFI `poll()` on stdin.

## Commands

Run everything from the **repo root** — modules use `require("src.*")` / `require("plugins.*")`, which resolve via `./?.lua` relative to the CWD, not the script dir. Running `luajit test.lua` from `src/` fails on the first require.

```bash
luajit src/test.lua    # full test suite (no framework; hand-rolled check() with pass/fail counts)
luajit src/main.lua    # interactive prompt: s = server, c = client
```

There is no linter, formatter, typechecker, or CI. `luajit src/test.lua` is the only automated verification. Do not use a stale compiled `main.luac` (gitignored).

## Architecture

- Single entrypoint `src/main.lua`; it prompts for server/client mode when run without args. Host/port default to `127.0.0.1:8888` but are CLI-configurable: `luajit src/main.lua s --host 0.0.0.0 --port 9000 --logs` / `luajit src/main.lua c --host H --port P --name N` (`-h` for usage).
- `src/server.lua`: blind relay + X3DH prekey directory. Never decrypts; stores public prekey bundles (one OPK consumed per fetch) and routes ciphertext. Wire protocol: newline-terminated JSON frames over TCP (`register | prekey_request | message | global | bye` → `registered | prekey_bundle | message | system | roster | error`).
- `src/crypto.lua`: all crypto via OpenSSL EVP through LuaJIT FFI (X25519, Ed25519, HKDF-SHA256, HMAC-SHA256, AES-256-GCM). Key material crosses JSON as lowercase hex; raw bytes internally.
- `src/double_ratchet.lua`: Double Ratchet state machine; per-recipient sessions live in `client.sessions` (in-memory only). Keys are regenerated every run — no persistence.
- `src/plugin.lua`: event hooks + message middleware. Sample plugin `plugins/logger.lua` is loaded via `pcall` in `main.lua` (safe if the directory is absent). Plugin API documented in `Docs/plugins.md`.

## Testing notes

- `src/test.lua` validates RFC 4231/5869 known-answer vectors plus X3DH and Double Ratchet roundtrips (out-of-order, replay, tamper). It also requires `src.client` near the end, so client-side changes are partially covered.
- Manual multi-terminal testing: start server with `luajit src/main.lua` (choose `s`, then `y/n` for connection logs), then clients in separate terminals (choose `c`). Usernames: 1–16 chars, `[A-Za-z0-9_]`. `/fingerprint [@user]` shows 60-digit safety numbers for out-of-band MITM verification.
