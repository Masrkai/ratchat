-- server_main.lua - ratchat server entrypoint (blind relay + X3DH prekey
-- directory). Loads server-scoped plugins from plugins/ before starting.
io.stdout:setvbuf("line") -- responsive output even when redirected/piped

local VERSION = "0.1.0"

local server_mod = require("src.server")
local plugin_manager = require("src.plugin")
local cli = require("src.cli")

-- CLI usage:
--   luajit src/server_main.lua [--host 0.0.0.0] [--port 9000] [--logs] [--logfile log.txt]
local function usage()
    print("Usage: luajit src/server_main.lua [options]")
    print("  --host HOST      bind address (default 127.0.0.1; use 0.0.0.0 to accept remote clients)")
    print("  --port PORT      TCP port (default 8888)")
    print("  --logs           enable connection logs on stdout")
    print("  --logfile FILE   append all server logs to FILE (e.g. log.txt)")
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
print("Mode: server")

local host = opts.host or "127.0.0.1"
local port = opts.port or 8888

-- Server-scoped plugins only (see plugins/logger.lua for an example).
plugin_manager:load_dir("plugins", "server")

local log_connections = opts.logs and true or false

-- Optional logfile: opened in append mode and handed to the server, which
-- tees every log line into it (timestamped) in addition to stdout.
local logfile = nil
if opts.logfile then
    logfile = io.open(opts.logfile, "a")
    if not logfile then
        print("[Error] Cannot open logfile '" .. opts.logfile .. "' for appending.")
        return
    end
    logfile:setvbuf("line")
end

local s = server_mod.new(host, port, log_connections, logfile)
local ok, run_err = pcall(function() s:start() end)
if logfile then logfile:close() end
if not ok then
    if tostring(run_err):find("interrupted", 1, true) then
        print("\n[Server] Shut down.")
    else
        print("[Server] Fatal: " .. tostring(run_err))
    end
end
