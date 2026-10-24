-- plugin.lua - Extensible Plugin System for E2EE Chat
local PluginManager = {
    plugins = {},
    listeners = {},
    middleware_pipeline = {}
}

function PluginManager:register(plugin)
    table.insert(self.plugins, plugin)
    if plugin.on_load then
        plugin.on_load(self)
    end
    print(string.format("[Plugin] Loaded: %s (v%s)", plugin.name or "Unnamed", plugin.version or "1.0"))
end

function PluginManager:on(event_name, callback)
    self.listeners[event_name] = self.listeners[event_name] or {}
    table.insert(self.listeners[event_name], callback)
end

function PluginManager:emit(event_name, ...)
    if self.listeners[event_name] then
        for _, cb in ipairs(self.listeners[event_name]) do
            local ok, err = pcall(cb, ...)
            if not ok then
                print(string.format("[Plugin] Error in '%s' handler: %s", event_name, tostring(err)))
            end
        end
    end
end

-- Filter pipeline: run all listeners for an event over a value, letting each
-- one return a transformed replacement (e.g. display-side text colorizing).
-- Non-string returns (including errors, which are pcall-caught) are ignored.
function PluginManager:filter(event_name, value, ...)
    local listeners = self.listeners[event_name]
    if listeners then
        for _, cb in ipairs(listeners) do
            local ok, newv = pcall(cb, value, ...)
            if ok and type(newv) == "string" then
                value = newv
            end
        end
    end
    return value
end

function PluginManager:use_middleware(fn)
    table.insert(self.middleware_pipeline, fn)
end

function PluginManager:process_message(ctx)
    for _, handler in ipairs(self.middleware_pipeline) do
        ctx = handler(ctx)
        if ctx and ctx.aborted then
            break
        end
    end
    return ctx
end

return PluginManager
