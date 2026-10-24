# Plugin System Guide: Extending the Lua Chat Client & Server

The Lua E2EE chat system features a modular, event-driven plugin architecture (`src/plugin.lua`). This allows developers to easily extend functionality—such as connection logging or display colorizing—without modifying the core application code.

---

## Architecture Overview

The plugin manager (`PluginManager`) provides two primary extension mechanisms:
1. **Directory-Based Auto-Discovery**: Each entrypoint scans `plugins/*.lua` and loads only the plugins matching its workload.
2. **Event-Driven Hook Bus (Pub/Sub)**: Lifecycle hooks (`on_load`, `server_started`, `client_connected`, `client_joined`, `client_left`) triggered by application events, plus a display **filter** chain used by the client to transform output text.

Plugins run in a single process per workload: the server (`src/server_main.lua`) and the client (`src/client_main.lua`) are separate executables, each with its own plugin manager instance and its own set of loaded plugins.

---

## Writing a Plugin

Create a new file inside the `plugins/` directory (e.g., `plugins/logger.lua`). Every plugin **must declare an explicit `scope`** — `"server"` or `"client"` — so the entrypoints know which workload it belongs to. Plugins without a `scope` field are skipped with a warning; plugins scoped for the other workload are skipped silently.

```lua
-- plugins/logger.lua
local LoggerPlugin = {
    name = "MessageLogger",
    version = "1.0",
    scope = "server",  -- required: "server" or "client"

    -- Called when the plugin is registered
    on_load = function(manager)
        print("[Plugin: Logger] Initialized successfully.")

        -- Listen to core system events
        manager:on("client_joined", function(username)
            print(string.format("[Event] User joined chat: %s", username))
        end)
    end
}

return LoggerPlugin
```

A client-side plugin hooks the display filter instead:

```lua
-- plugins/shout.lua
return {
    name = "Shout",
    version = "1.0",
    scope = "client",

    on_load = function(manager)
        manager:on("display", function(text)
            return text:upper()
        end)
    end
}
```

### Available events

| Event              | Scope  | Fired with                     | Notes                                        |
|--------------------|--------|--------------------------------|----------------------------------------------|
| `server_started`   | server | `ip, port`                     | Once, after the listen socket is bound.      |
| `client_connected` | server | raw socket object              | Before registration (name may be nil).       |
| `client_joined`    | server | `username`                     | After a successful `register`.               |
| `client_left`      | server | `username`                     | On disconnect.                               |
| `client_joined`    | client | `username`                     | Fired locally after connecting.              |
| `display` (filter) | client | `text, is_async` → new `text`  | Transforms each line before it is printed.   |

Filter handlers must return a string to replace the value; non-string returns (including errors, which are pcall-caught) are ignored and the value passes through unchanged.

---

## How Plugins Are Loaded

Each entrypoint calls `PluginManager:load_dir("plugins", scope)` at startup:

```lua
-- src/server_main.lua
local plugin_manager = require("src.plugin")
plugin_manager:load_dir("plugins", "server")
```

`load_dir` lists `plugins/*.lua`, requires each module, and registers only plugins whose `scope` matches. Loading is failure-tolerant: a missing `plugins/` directory, an unreadable file, or a broken plugin never prevents startup. No manual registration is needed — dropping a correctly-scoped file into `plugins/` is enough.

---

## Best Practices

1. **Non-Blocking Execution**: Keep plugin hooks lightweight and synchronous so they don't block socket I/O loops.
2. **Isolation**: Avoid global variable pollution inside plugins; encapsulate all state within the returned plugin table.
3. **Display-Only on the Client**: Client plugins should transform text for display only — never touch the wire protocol or the crypto layer.
