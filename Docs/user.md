# User Guide: Signal-Encrypted Lua Chat Client

Welcome to the End-to-End Encrypted Chat Client! This guide explains how to set up your environment, launch the client, and securely message other users using the Signal Protocol (X3DH + Double Ratchet).

---

## Prerequisites

Ensure you have **Nix** installed on your system to easily spin up the development environment with LuaJIT, LuaSocket, and OpenSSL.

1. Clone the repository and enter the directory:
   ```bash
   git clone https://github.com/Masrkai/End-to-End-Encrypted_Chat-Server.git
   cd End-to-End-Encrypted_Chat-Server
   ```
2. Enter the reproducible development shell:
   ```bash
   nix-shell
   ```

---

## Starting the Client

1. Launch the interactive main script:
   ```bash
   luajit src/main.lua
   ```
2. When prompted for mode, select **`c`** for client mode.
3. Enter your unique **username** (e.g., `Alice` or `Bob`).

### Command-line options

Both modes can be started non-interactively with CLI flags (defaults: `127.0.0.1:8888`):

```bash
# Run a server on all interfaces, port 9000, with connection logs
luajit src/main.lua s --host 0.0.0.0 --port 9000 --logs

# Connect a client to any server instance
luajit src/main.lua c --host chat.example.com --port 9000 --name Alice
```

| Flag | Applies to | Meaning |
|---|---|---|
| `--host HOST` | both | Bind address (server) / server address (client). Use `0.0.0.0` to accept remote clients. |
| `--port PORT` | both | TCP port (1–65535, default 8888) |
| `--name NAME` | client | Username (skips the prompt; must be 1–16 letters/digits/underscores) |
| `--logs` | server | Enable connection logs |
| `-h, --help` | both | Show usage |

Anyone can run their own server instance; clients simply point at whichever server they choose. Users on different servers are separate communities and cannot see each other (no federation).

---

## Messaging & Key Exchange

- Upon connection, your client automatically generates your **Identity Key (IK)**, **Signed Prekey (SPK)**, **One-Time Prekeys (OPK)** and an **Ed25519 signing key**, then uploads the public prekey bundle to the server.
- Everyone online receives a `[Global] @you has joined the chat.` notice.

### Chat commands

| Input | Effect |
|---|---|
| `hello` | Send to the **global room** (encrypted separately for each online member) |
| `@Bob hi bob` | Direct message to `@Bob` |
| `/who` | List online users |
| `/fingerprint` | Show **your** 60-digit safety number |
| `/fingerprint @Bob` | Show **@Bob's** safety number (after your first exchange) |
| `/help` | Show help |
| `exit` | Quit |

Incoming messages and join/leave notices appear **live while you type**.

### How a session is established

1. Sending to a user for the first time makes your client request their **Prekey Bundle** from the server (one One-Time Prekey is consumed per fetch).
2. Your client verifies the **Ed25519 signature** on their Signed Prekey (aborting on mismatch — MITM guard), performs **X3DH** to derive a shared secret, and boots the **Double Ratchet**.
3. The first message carries the X3DH parameters so the recipient can derive the same secret on their side; subsequent messages ratchet forward automatically.
4. If both users message each other simultaneously (session collision), the clients detect it and re-converge on the next exchange.

### Verifying a session (MITM protection)

The server hands out prekey bundles, so a malicious server could substitute its own keys and sit in the middle of your first exchange. To rule this out, compare **safety numbers** with your peer over a channel the server can't influence (in person, voice call):

```
/fingerprint @Bob
[Fingerprint] @Bob: 23790 81345 41593 33553 80317 94422 51300 19721 69447 99904 34722 64095
```

Both sides run `/fingerprint` on each other and compare the 60 digits. If they match, your session keys were derived from each other's genuine identity keys. A peer's fingerprint becomes available after your first message exchange (when their identity key is pinned locally).

---

## Running Tests

To verify that all cryptographic primitives and networking modules are working correctly:
```bash
luajit src/test.lua
```
