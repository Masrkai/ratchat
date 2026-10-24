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

print("=== ratchat " .. VERSION .. " — End-to-End Encrypted Chat (LuaJIT) ===")
print("Select mode:")
print("  s - Server mode")
print("  c - Client mode")
io.write("Enter choice (s/c): ")
io.flush()

local choice = io.read()

if choice == "s" then
    io.write("Enable connection logs? (y/n): ")
    io.flush()
    local ans = io.read() or ""
    local log_connections = ans:match("^%s*[yY]") and true or false

    local s = server_mod.new("127.0.0.1", 8888, log_connections)
    local ok, err = pcall(function() s:start() end)
    if not ok then
        if tostring(err):find("interrupted", 1, true) then
            print("\n[Server] Shut down.")
        else
            print("[Server] Fatal: " .. tostring(err))
        end
    end

elseif choice == "c" then
    local username = prompt_username("Enter your username: ")
    if not username then return end

    local c = client_mod.new(username, "127.0.0.1", 8888)
    local ok, err = c:connect()

    -- Re-prompt on rejected usernames
    while not ok and (err == "name_taken" or err == "bad_name") do
        if err == "name_taken" then
            print("[Error] Username '" .. c.username .. "' is already taken.")
        end
        local new_name = prompt_username("Enter a different username: ")
        if not new_name then return end
        c = client_mod.new(new_name, "127.0.0.1", 8888)
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
