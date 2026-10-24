-- client_main.lua - ratchat client entrypoint (X3DH + Double Ratchet chat
-- loop). Loads client-scoped plugins from plugins/ before connecting.
io.stdout:setvbuf("line") -- responsive output even when redirected/piped

local VERSION = "0.1.0"

local client_mod = require("src.client")
local plugin_manager = require("src.plugin")
local cli = require("src.cli")

-- CLI usage:
--   luajit src/client_main.lua [--host chat.example.com] [--port 9000] [--name alice]
local function usage()
    print("Usage: luajit src/client_main.lua [options]")
    print("  --host HOST      connect address (default 127.0.0.1)")
    print("  --port PORT      TCP port (default 8888)")
    print("  --name NAME      username (skips the prompt)")
    print("  -h, --help       show this help")
end

local opts, err = cli.parse_args(arg or {})
if not opts then
    print("[Error] " .. err)
    return
end
if opts.help then
    usage()
    return
end

print("=== ratchat " .. VERSION .. " — End-to-End Encrypted Chat (LuaJIT) ===")
print("Mode: client")

local host = opts.host or "127.0.0.1"
local port = opts.port or 8888

-- Client-scoped plugins only (see plugins/colorize.lua for an example).
plugin_manager:load_dir("plugins", "client")

local username = opts.name
if username then
    if not cli.valid_username(username) then
        print("[Error] Invalid --name '" .. username .. "': must be 1-16 letters, digits or underscores.")
        return
    end
else
    username = cli.prompt_username("Enter your username: ")
    if not username then return end
end

local c = client_mod.new(username, host, port)
local ok, connect_err = c:connect()

-- Re-prompt on rejected usernames
while not ok and (connect_err == "name_taken" or connect_err == "bad_name") do
    if connect_err == "name_taken" then
        print("[Error] Username '" .. c.username .. "' is already taken.")
    end
    local new_name = cli.prompt_username("Enter a different username: ")
    if not new_name then return end
    c = client_mod.new(new_name, host, port)
    ok, connect_err = c:connect()
end

if not ok then
    print("[Error] " .. tostring(connect_err))
    return
end

local ok2, err2 = pcall(function() c:start_chat_loop() end)
if not ok2 then
    if tostring(err2):find("interrupted", 1, true) then
        print("\nGoodbye.")
    else
        print("[Error] " .. tostring(err2))
    end
end
