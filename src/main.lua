-- main.lua - ratchat: E2EE chat (X3DH + Double Ratchet) in LuaJIT
io.stdout:setvbuf("line") -- responsive output even when redirected/piped

local VERSION = "0.1.0"

local server_mod = require("src.server")
local client_mod = require("src.client")
local plugin_manager = require("src.plugin")

-- Optional sample plugin (safe if the plugins/ directory is absent)
pcall(function() plugin_manager:register(require("plugins.logger")) end)

local function valid_username(s)
    return type(s) == "string" and #s >= 1 and #s <= 16 and s:match("^[%w_]+$") ~= nil
end

-- CLI usage:
--   luajit src/main.lua s [--host 0.0.0.0] [--port 9000] [--logs]
--   luajit src/main.lua c [--host chat.example.com] [--port 9000] [--name alice]
-- With no arguments the interactive prompts are used (defaults: 127.0.0.1:8888).
local function usage()
    print("Usage: luajit src/main.lua [s|c] [options]")
    print("  s                run a server (blind relay + prekey directory)")
    print("  c                run a client")
    print("  --host HOST      bind/connect address (default 127.0.0.1; use 0.0.0.0 to accept remote clients)")
    print("  --port PORT      TCP port (default 8888)")
    print("  --name NAME      client username (skips the prompt)")
    print("  --logs           server: enable connection logs")
    print("  -h, --help       show this help")
end

local function parse_args(argv)
    local opts = { mode = nil, host = nil, port = nil, name = nil, logs = nil }
    local i = 1
    while i <= #argv do
        local a = argv[i]
        if a == "s" or a == "c" then
            opts.mode = a
        elseif a == "--host" then
            i = i + 1
            if not argv[i] then error("--host expects a value") end
            opts.host = argv[i]
        elseif a == "--port" then
            i = i + 1
            opts.port = tonumber(argv[i])
            if not opts.port or opts.port < 1 or opts.port > 65535 then
                error("--port expects a number between 1 and 65535")
            end
        elseif a == "--name" then
            i = i + 1
            if not argv[i] then error("--name expects a value") end
            opts.name = argv[i]
        elseif a == "--logs" then
            opts.logs = true
        elseif a == "--help" or a == "-h" then
            opts.help = true
        else
            error("unknown argument: " .. tostring(a) .. " (try --help)")
        end
        i = i + 1
    end
    return opts
end

local function prompt_username(label)
    while true do
        io.write(label)
        io.flush()
        local input = io.read()
        if not input then return nil end -- EOF
        input = input:match("^%s*(.-)%s*$")
        if valid_username(input) then
            return input
        end
        print("[Error] Username must be 1-16 letters, digits or underscores.")
    end
end

local opts = parse_args(arg or {})
if opts.help then
    usage()
    return
end

print("=== ratchat " .. VERSION .. " — End-to-End Encrypted Chat (LuaJIT) ===")

local mode = opts.mode
if not mode then
    print("Select mode:")
    print("  s - Server mode")
    print("  c - Client mode")
    io.write("Enter choice (s/c): ")
    io.flush()
    mode = io.read()
end

local host = opts.host or "127.0.0.1"
local port = opts.port or 8888

if mode == "s" then
    local log_connections = opts.logs
    if log_connections == nil and not opts.mode then
        -- Only prompt when the mode itself came from the interactive flow.
        io.write("Enable connection logs? (y/n): ")
        io.flush()
        local ans = io.read() or ""
        log_connections = ans:match("^%s*[yY]") and true or false
    end
    log_connections = log_connections and true or false

    local s = server_mod.new(host, port, log_connections)
    local ok, err = pcall(function() s:start() end)
    if not ok then
        if tostring(err):find("interrupted", 1, true) then
            print("\n[Server] Shut down.")
        else
            print("[Server] Fatal: " .. tostring(err))
        end
    end

elseif mode == "c" then
    local username = opts.name
    if username then
        if not valid_username(username) then
            print("[Error] Invalid --name '" .. username .. "': must be 1-16 letters, digits or underscores.")
            return
        end
    else
        username = prompt_username("Enter your username: ")
        if not username then return end
    end

    local c = client_mod.new(username, host, port)
    local ok, err = c:connect()

    -- Re-prompt on rejected usernames
    while not ok and (err == "name_taken" or err == "bad_name") do
        if err == "name_taken" then
            print("[Error] Username '" .. c.username .. "' is already taken.")
        end
        local new_name = prompt_username("Enter a different username: ")
        if not new_name then return end
        c = client_mod.new(new_name, host, port)
        ok, err = c:connect()
    end

    if not ok then
        print("[Error] " .. tostring(err))
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

else
    print("Invalid choice. Exiting.")
end
