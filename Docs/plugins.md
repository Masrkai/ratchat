# Plugin System Guide: Extending the Lua Chat Client & Server

The Lua E2EE chat system features a modular, event-driven, and middleware-based plugin architecture (`src/plugin.lua`). This allows developers to easily extend functionality—such as message logging, profanity filtering, custom encryption wrappers, or telemetry—without modifying the core application code.

---

## Architecture Overview

The plugin manager (`PluginManager`) provides three primary extension mechanisms:
1. **Directory-Based Loading / Registration**: Plugins register themselves with the core application.
2. **Event-Driven Hook Bus (Pub/Sub)**: Lifecycle hooks (`on_load`, `server_started`, `client_connected`, `client_joined`) triggered by application events.
3. **Middleware Pipeline**: Sequential interception and transformation of message contexts before transmission or after receipt.

---

## Writing a Plugin

Create a new file inside a `plugins/` directory (e.g., `plugins/logger.lua`):

```lua
-- plugins/logger.lua
local LoggerPlugin = {
    name = "MessageLogger",
    version = "1.0",
    
    -- Called when the plugin is registered
    on_load = function(manager)
        print("[Plugin: Logger] Initialized successfully.")
        
        -- Listen to core system events
        manager:on("client_joined", function(username)
            print(string.format("[Event] User joined chat: %s", username))
        end)
        
        -- Register a message middleware handler
        manager:use_middleware(function(ctx)
            print(string.format("[Middleware] Message from %s to @%s: %s", ctx.sender, ctx.recipient, ctx.message))
            
            -- Example: Profanity filter / word replacement
            ctx.message = ctx.message:gsub("badword", "****")
            
            return ctx
        end)
    end
}

return LoggerPlugin
```

---

## Registering Plugins

In your application startup (`src/main.lua` or server/client initialization), load and register your plugins:

```lua
local plugin_manager = require("src.plugin")
local logger_plugin = require("plugins.logger")

-- Register plugin
plugin_manager:register(logger_plugin)
```

---

## Best Practices

1. **Non-Blocking Execution**: Keep plugin hooks lightweight and synchronous so they don't block socket I/O loops.
2. **Context Mutability**: In message middleware, always return the mutated `ctx` table (or return `{ aborted = true }` if you need to drop/block a message).
3. **Isolation**: Avoid global variable pollution inside plugins; encapsulate all state within the returned plugin table.
