-- server.lua - Signal Protocol Prekey Directory & Chat Relay Server in Lua
--
-- The server is a blind relay:
--   * stores and hands out clients' X3DH prekey bundles (one OPK consumed per fetch)
--   * routes encrypted payloads between clients without being able to read them
--   * maintains a global room: join/leave notices + roster broadcasts
--
-- Wire protocol: newline-terminated JSON frames over TCP.
--   C->S: register | prekey_request | message | global | bye
--   S->C: registered | prekey_bundle | message | system | roster | error

local socket = require("socket")
local json = require("cjson")
local plugin_manager = require("src.plugin")

local ChatServer = {}
ChatServer.__index = ChatServer

local function valid_username(s)
    return type(s) == "string" and #s >= 1 and #s <= 16 and s:match("^[%w_]+$") ~= nil
end

function ChatServer.new(host, port, log_connections)
    local self = setmetatable({}, ChatServer)
    self.host = host or "127.0.0.1"
    self.port = port or 8888
    self.log_connections = log_connections and true or false
    self.prekey_bundles = {} -- username -> { ik, spk, spk_sig, ed_id, opks = { {id, pub, used} } }
    self.clients = {}        -- sock -> { name, buf, ip, port }
    self.by_name = {}        -- username -> sock
    self.running = false
    return self
end

-- Conditional logging (connection/registration/disconnection activity)
function ChatServer:log(fmt, ...)
    if self.log_connections then
        print(string.format("[Server] " .. fmt, ...))
    end
end

function ChatServer:send_json(sock, tbl)
    local c = self.clients[sock]
    if not c then return false end
    local ok, err = pcall(function()
        sock:send(json.encode(tbl) .. "\n")
    end)
    if not ok then
        self:disconnect(sock, "send failed: " .. tostring(err))
        return false
    end
    return true
end

-- Broadcast to every registered client, optionally excluding one socket.
-- Works for unregistered sockets too when exclude is nil and all are unregistered.
function ChatServer:broadcast(tbl, exclude_sock)
    local targets = {}
    for sock, c in pairs(self.clients) do
        if c.name and sock ~= exclude_sock then
            targets[#targets + 1] = sock
        end
    end
    for _, sock in ipairs(targets) do
        self:send_json(sock, tbl)
    end
end

function ChatServer:roster_list()
    local names = {}
    for name in pairs(self.by_name) do
        names[#names + 1] = name
    end
    table.sort(names)
    return names
end

function ChatServer:online_count()
    local n = 0
    for _ in pairs(self.by_name) do n = n + 1 end
    return n
end

function ChatServer:start()
    local server, err = socket.bind(self.host, self.port)
    if not server then
        print(string.format("[Server] Failed to bind %s:%d (%s)", self.host, self.port, tostring(err)))
        print("[Server] Is another server already running on this port?")
        return false
    end
    server:settimeout(0.5)
    local ip, port = server:getsockname()
    print(string.format("[Server] Signal-Protocol E2EE Server started on %s:%d", ip, port))
    plugin_manager:emit("server_started", ip, port)
    self.running = true

    local ok, loop_err = pcall(function()
        while self.running do
            local read_list = { server }
            for sock in pairs(self.clients) do
                read_list[#read_list + 1] = sock
            end
            local readable, sel_err = socket.select(read_list, nil, 0.5)
            if readable then
                for _, sock in ipairs(readable) do
                    if not self.running then break end
                    if sock == server then
                        self:accept_client(server)
                    else
                        self:handle_readable(sock)
                    end
                end
            elseif sel_err ~= "timeout" then
                self:log("[Server] select error: %s", tostring(sel_err))
            end
        end
    end)

    if not ok then
        if tostring(loop_err):find("interrupted", 1, true) then
            print("\n[Server] Interrupt received, shutting down.")
        else
            print("[Server] Fatal error: " .. tostring(loop_err))
        end
    end

    -- Graceful shutdown: notify clients, then close everything.
    for sock in pairs(self.clients) do
        pcall(function() sock:send(json.encode({ type = "system", text = "Server is shutting down." }) .. "\n") end)
        pcall(function() sock:close() end)
    end
    self.clients = {}
    self.by_name = {}
    pcall(function() server:close() end)
    print("[Server] Shut down.")
    return true
end

function ChatServer:accept_client(server)
    local sock, err = server:accept()
    if not sock then return end
    sock:settimeout(0)
    local ip, cport = sock:getpeername()
    self.clients[sock] = { name = nil, buf = "", ip = ip, port = cport }
    self:log("Connection from %s:%d", tostring(ip), tonumber(cport) or 0)
    plugin_manager:emit("client_connected", sock)
end

function ChatServer:handle_readable(sock)
    local c = self.clients[sock]
    if not c then return end

    local data, err, partial = sock:receive(8192)
    if data then c.buf = c.buf .. data end
    if partial and #partial > 0 then c.buf = c.buf .. partial end

    while true do
        local nl = c.buf:find("\n", 1, true)
        if not nl then break end
        local line = c.buf:sub(1, nl - 1)
        c.buf = c.buf:sub(nl + 1)
        if #line > 0 then
            self:dispatch(sock, line)
        end
        if not self.clients[sock] then return end -- disconnected during dispatch
    end

    if err and err ~= "timeout" then
        self:disconnect(sock, err)
    end
end

function ChatServer:dispatch(sock, line)
    local ok, pkt = pcall(json.decode, line)
    if not ok or type(pkt) ~= "table" or type(pkt.type) ~= "string" then
        self:send_json(sock, { type = "error", code = "bad_packet", detail = "invalid JSON frame" })
        return
    end

    local c = self.clients[sock]
    local t = pkt.type

    if t == "register" then
        self:handle_register(sock, pkt)
    elseif not c.name then
        self:send_json(sock, { type = "error", code = "not_registered", detail = "register first" })
    elseif t == "prekey_request" then
        self:handle_prekey_request(sock, pkt)
    elseif t == "message" then
        self:handle_message(sock, pkt)
    elseif t == "global" then
        self:handle_global(sock, pkt)
    elseif t == "bye" then
        self:disconnect(sock, "client said bye")
    else
        self:send_json(sock, { type = "error", code = "bad_packet", detail = "unknown type: " .. t })
    end
end

function ChatServer:handle_register(sock, pkt)
    local c = self.clients[sock]
    local name = tostring(pkt.username or "")

    if not valid_username(name) then
        self:send_json(sock, { type = "error", code = "bad_name", detail = "1-16 letters, digits or underscores" })
        return
    end
    if self.by_name[name] then
        self:send_json(sock, { type = "error", code = "name_taken", detail = name })
        return
    end

    local b = pkt.bundle
    if type(b) ~= "table" or type(b.ik) ~= "string" or type(b.spk) ~= "string"
        or type(b.spk_sig) ~= "string" or type(b.ed_id) ~= "string" then
        self:send_json(sock, { type = "error", code = "bad_packet", detail = "missing prekey bundle" })
        return
    end

    local opks = {}
    if type(b.opks) == "table" then
        for _, o in ipairs(b.opks) do
            if type(o) == "table" and type(o.id) == "number" and type(o.pub) == "string" then
                opks[#opks + 1] = { id = o.id, pub = o.pub, used = false }
            end
        end
    end

    c.name = name
    self.by_name[name] = sock
    self.prekey_bundles[name] = { ik = b.ik, spk = b.spk, spk_sig = b.spk_sig, ed_id = b.ed_id, opks = opks }

    self:send_json(sock, { type = "registered", username = name })
    self:broadcast({ type = "roster", members = self:roster_list() })
    self:broadcast({ type = "system", text = "@" .. name .. " has joined the chat." }, sock)
    self:log("@%s registered (global room: %d online)", name, self:online_count())
    plugin_manager:emit("client_joined", name)
end

function ChatServer:handle_prekey_request(sock, pkt)
    local target = tostring(pkt.recipient or "")
    local stored = self.prekey_bundles[target]
    if not stored then
        self:send_json(sock, { type = "error", code = "unknown_user", detail = target })
        return
    end
    -- Consume one unused one-time prekey (Signal behaviour); may be nil if exhausted.
    local opk = nil
    for _, o in ipairs(stored.opks) do
        if not o.used then
            o.used = true
            opk = { id = o.id, pub = o.pub }
            break
        end
    end
    self:send_json(sock, {
        type = "prekey_bundle",
        recipient = target,
        bundle = { ik = stored.ik, spk = stored.spk, spk_sig = stored.spk_sig, ed_id = stored.ed_id, opk = opk }
    })
end

function ChatServer:handle_message(sock, pkt)
    local sender = self.clients[sock].name
    if type(pkt.payload) ~= "table" then
        self:send_json(sock, { type = "error", code = "bad_packet", detail = "missing payload" })
        return
    end
    local target_sock = self.by_name[tostring(pkt.recipient or "")]
    if not target_sock then
        self:send_json(sock, { type = "error", code = "user_offline", detail = tostring(pkt.recipient or "") })
        return
    end
    self:send_json(target_sock, { type = "message", sender = sender, payload = pkt.payload })
end

function ChatServer:handle_global(sock, pkt)
    local sender = self.clients[sock].name
    if type(pkt.items) ~= "table" then
        self:send_json(sock, { type = "error", code = "bad_packet", detail = "missing items" })
        return
    end
    for _, item in ipairs(pkt.items) do
        if type(item) == "table" and type(item.to) == "string" and type(item.payload) == "table" then
            local target_sock = self.by_name[item.to]
            if target_sock then
                self:send_json(target_sock, { type = "message", sender = sender, payload = item.payload })
            end
        end
    end
end

function ChatServer:disconnect(sock, reason)
    local c = self.clients[sock]
    if not c then return end
    self.clients[sock] = nil

    if c.name then
        self.by_name[c.name] = nil
        self.prekey_bundles[c.name] = nil
        self:broadcast({ type = "system", text = "@" .. c.name .. " has left the chat." })
        self:broadcast({ type = "roster", members = self:roster_list() })
        self:log("@%s disconnected (%s)", c.name, tostring(reason or "closed"))
        plugin_manager:emit("client_left", c.name)
    else
        self:log("Connection from %s:%d closed", tostring(c.ip), tonumber(c.port) or 0)
    end
    pcall(function() sock:close() end)
end

return ChatServer
