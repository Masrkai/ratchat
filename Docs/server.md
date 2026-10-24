# Server Hosting Guide: Signal-Encrypted Chat Relay

This guide provides instructions on how to host the central chat relay server and Prekey Directory for clients to connect to.

---

## Architecture Role

The server acts as a **relay and Prekey Directory**:
- **Zero Decryption**: The server forwards encrypted ciphertexts between clients. It does not possess client private keys and cannot read messages.
- **Prekey Directory**: Stores and distributes clients' X3DH Prekey Bundles (`IK`, `SPK`, `OPK`) to facilitate asynchronous initial key exchange.

---

## Hosting Instructions

### 1. Environment Setup
Make sure you are inside the Nix development shell (which provides LuaJIT, LuaSocket, and OpenSSL):
```bash
nix-shell
```

### 2. Starting the Server
Run the main entry point script:
```bash
luajit src/main.lua
```
When prompted for mode, select **`s`** for server mode. You will then be asked
whether to enable **connection logs** (`y/n`) — with logs enabled the server
prints every connection, registration and disconnection; with logs disabled it
stays quiet except for startup and errors.

The server automatically puts every registered client into the **global chat
room**, broadcasts `@name has joined/left the chat.` notices, and keeps all
clients' rosters in sync.

### 3. Network Configuration
- By default, the server binds to `127.0.0.1` on port `8888`.
- To host on a public IP or custom port, edit `src/main.lua`:
  ```lua
  local s = server.new("0.0.0.0", 8888)
  ```
- Ensure your firewall allows incoming TCP traffic on your chosen port.
