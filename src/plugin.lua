-- plugin.lua - Extensible Plugin System for E2EE Chat
--
-- Plugins declare a required `scope` field ("server" or "client"); the
-- entrypoints (src/server_main.lua / src/client_main.lua) load only the
-- plugins matching their workload via PluginManager:load_dir().
local PluginManager = {
    plugins = {},
    listeners = {},
    verbose = false -- when true, [Plugin] Loaded lines are printed on register
}

function PluginManager:register(plugin)
    table.insert(self.plugins, plugin)
    if plugin.on_load then
        plugin.on_load(self)
    end
    if self.verbose then
        print(string.format("[Plugin] Loaded: %s (v%s)", plugin.name or "Unnamed", plugin.version or "1.0"))
    end
end

-- Discover and register plugins from a directory, filtered by workload.
-- Only plugins whose `scope` field exactly matches `scope` are registered;
-- plugins without an explicit scope are skipped with a warning.
-- Every failure (missing directory, unreadable file, broken plugin) is
-- swallowed so a bad plugin can never prevent startup.
function PluginManager:load_dir(dir, scope)
    local ok, listing = pcall(function()
        local pipe = io.popen("ls " .. dir .. "/*.lua 2>/dev/null")
        if not pipe then return nil end
        local files = {}
        for line in pipe:lines() do
            files[#files + 1] = line
        end
        pipe:close()
        return files
    end)
    if not ok or type(listing) ~= "table" then return end

    for _, path in ipairs(listing) do
        local base = path:match("([^/]+)%.lua$")
        if base then
            local modname = dir:gsub("[/\\]", ".") .. "." .. base
            local lok, plugin = pcall(require, modname)
            if lok and type(plugin) == "table" then
                if plugin.scope == scope then
                    self:register(plugin)
                elseif plugin.scope == "server" or plugin.scope == "client" then
                    -- Belongs to the other workload; skip silently.
                else
                    print(string.format(
                        "[Plugin] Skipped '%s': no explicit scope (add scope = \"server\" or \"client\")",
                        plugin.name or base))
                end
            end
        end
    end
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

return PluginManager
