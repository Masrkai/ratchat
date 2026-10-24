-- client.lua - Signal Protocol E2EE Chat Client in Lua with Interactive REPL
--
-- * Registers with the server and uploads its X3DH prekey bundle
-- * Fetches recipients' bundles, verifies SPK signatures, runs X3DH (initiator)
-- * Answers inbound X3DH from the first received message (receiver)
-- * Live receive while typing: FFI poll() on stdin + socket (POSIX)
-- * Global room messages are encrypted pairwise per online member
--
-- Chat commands:
--   plain text          -> global room
--   @username message   -> direct message
--   /who | /fingerprint [@user] | /help | exit

local socket = require("socket")
local json = require("cjson")
local ffi = require("ffi")
local bit = require("bit")
local crypto_manager = require("src.crypto")
local double_ratchet = require("src.double_ratchet")
local plugin_manager = require("src.plugin")

ffi.cdef[[
    typedef struct pollfd { int fd; short events; short revents; } pollfd_t;
    int poll(pollfd_t *fds, unsigned long nfds, int timeout);
]]

local POLLIN = 1
local POLLHUP = 0x10

local ChatClient = {}
ChatClient.__index = ChatClient

function ChatClient.new(username, host, port)
    local self = setmetatable({}, ChatClient)
    self.username = username
    self.host = host or "127.0.0.1"
    self.port = port or 8888
    self.crypto = crypto_manager.new()
    self.sessions = {}      -- recipient -> DoubleRatchet
    self.peer_iks = {}      -- recipient -> identity pub hex (for associated data)
    self.x3dh_headers = {}  -- recipient -> X3DH block to attach to the first message
    self.roster = {}        -- list of online usernames (includes self)
    self.rbuf = ""          -- receive buffer for line framing
    self.running = true
    return self
end

-- ---------------------------------------------------------------------------
-- Low-level transport
-- ---------------------------------------------------------------------------

function ChatClient:send_raw(tbl)
    if not self.sock then return false end
    local ok, err = pcall(function()
        self.sock:send(json.encode(tbl) .. "\n")
    end)
    if not ok then
        print("[Client] Connection lost while sending (" .. tostring(err) .. ").")
        self.running = false
        return false
    end
    return true
end

-- Blocking line read with an overall timeout; used during handshake and
-- prekey fetches. Returns line, or nil + error reason.
--
-- NOTE: waits with socket.select() and reads non-blocking afterwards.
-- A plain blocking receive(N) would wait for ALL N bytes or the full timeout
-- even when a complete line is already available, deafening us for seconds.
function ChatClient:read_line(timeout)
    local deadline = socket.gettime() + (timeout or 3)
    while true do
        local nl = self.rbuf:find("\n", 1, true)
        if nl then
            local line = self.rbuf:sub(1, nl - 1)
            self.rbuf = self.rbuf:sub(nl + 1)
            return line
        end
        local remaining = deadline - socket.gettime()
        if remaining <= 0 then return nil, "timeout" end
        local ready = socket.select({ self.sock }, nil, remaining)
        if not ready or #ready == 0 then
            if socket.gettime() >= deadline then return nil, "timeout" end
        else
            self.sock:settimeout(0)
            local data, err, partial = self.sock:receive(8192)
            if data then
                self.rbuf = self.rbuf .. data
            elseif err == "timeout" then
                self.rbuf = self.rbuf .. (partial or "")
            else
                return nil, err or "closed"
            end
        end
    end
end

-- Dispatch every complete line currently buffered in rbuf.
-- Returns true, or false + error when the connection is gone.
function ChatClient:process_rbuf_lines()
    while true do
        local nl = self.rbuf:find("\n", 1, true)
        if not nl then break end
        local line = self.rbuf:sub(1, nl - 1)
        self.rbuf = self.rbuf:sub(nl + 1)
        if #line > 0 then
            local ok, pkt = pcall(json.decode, line)
            if ok and type(pkt) == "table" then
                self:handle_packet(pkt)
            end
        end
        if not self.running then return false, "closed" end
    end
    return true
end

-- Non-blocking drain of whatever has arrived, then dispatch buffered lines.
-- Returns true, or false + error when the connection is gone.
function ChatClient:try_read_available()
    local data, err, partial = self.sock:receive(8192)
    if data then self.rbuf = self.rbuf .. data end
    if partial and #partial > 0 then self.rbuf = self.rbuf .. partial end

    local ok, perr = self:process_rbuf_lines()
    if not ok then return false, perr end

    if err and err ~= "timeout" then
        return false, err
    end
    return true
end

-- ---------------------------------------------------------------------------
-- Connection / handshake
-- ---------------------------------------------------------------------------

function ChatClient:connect()
    local sock, err = socket.connect(self.host, self.port)
    if not sock then
        return nil, "Cannot reach server at " .. self.host .. ":" .. self.port ..
            " (" .. tostring(err) .. "). Is the server running?"
    end
    self.sock = sock
    self.rbuf = ""

    sock:settimeout(3)
    self:send_raw({ type = "register", username = self.username, bundle = self.crypto:get_upload_bundle() })

    while true do
        local line, lerr = self:read_line(3)
        if not line then
            pcall(function() sock:close() end)
            self.sock = nil
            return nil, "Handshake failed: server did not respond (" .. tostring(lerr) .. ")."
        end
        local ok, pkt = pcall(json.decode, line)
        if ok and type(pkt) == "table" then
            if pkt.type == "registered" then
                break
            elseif pkt.type == "error" then
                pcall(function() sock:close() end)
                self.sock = nil
                if pkt.code == "name_taken" then
                    return nil, "name_taken"
                elseif pkt.code == "bad_name" then
                    return nil, "bad_name"
                else
                    return nil, "Server rejected registration: " .. tostring(pkt.code)
                end
            elseif pkt.type == "roster" then
                self.roster = pkt.members or {}
            end
        end
    end

    sock:settimeout(0) -- non-blocking; the chat loop polls
    print(string.format("[Client] Connected to server as '%s' (Signal Protocol E2EE)", self.username))
    plugin_manager:emit("client_joined", self.username)
    return true
end

-- ---------------------------------------------------------------------------
-- Session establishment (X3DH) and messaging
-- ---------------------------------------------------------------------------

-- Print helper: async prints get a leading newline (prompt is mid-line),
-- then the input prompt is redrawn.
function ChatClient:print_line(text, is_async)
    if is_async then
        io.write("\n" .. text .. "\n")
    else
        print(text)
    end
    io.write("[" .. self.username .. "]> ")
    io.flush()
end

function ChatClient:establish_initiator(recipient, bundle)
    -- A session may already exist (e.g. established via inbound X3DH while we
    -- were waiting for this bundle). Never overwrite a live ratchet state.
    if self.sessions[recipient] then return true end

    if type(bundle) ~= "table" or type(bundle.ik) ~= "string" or type(bundle.spk) ~= "string"
        or type(bundle.spk_sig) ~= "string" or type(bundle.ed_id) ~= "string" then
        self:print_line("[Error] Malformed prekey bundle for @" .. recipient .. ".", true)
        return false
    end

    -- Verify the signed prekey against the identity's Ed25519 key (MITM guard)
    local sig_ok = self.crypto.ed25519_verify(bundle.ed_id, self.crypto.from_hex(bundle.spk), bundle.spk_sig)
    if not sig_ok then
        self:print_line("[Error] Invalid prekey signature for @" .. recipient ..
            " - possible MITM. Session aborted.", true)
        return false
    end

    local ok, sk, ek_pub = pcall(self.crypto.x3dh_initiator, self.crypto, bundle)
    if not ok or not sk then
        self:print_line("[Error] X3DH failed for @" .. recipient .. ": " .. tostring(ek_pub), true)
        return false
    end

    local rok, ratchet = pcall(double_ratchet.new, sk, true, bundle.spk, nil)
    if not rok or not ratchet then
        self:print_line("[Error] Ratchet init failed for @" .. recipient .. ": " .. tostring(ratchet), true)
        return false
    end

    self.sessions[recipient] = ratchet
    self.peer_iks[recipient] = bundle.ik
    self.x3dh_headers[recipient] = {
        ik = self.crypto.identity_key.public,
        ek = ek_pub,
        opk_id = bundle.opk and bundle.opk.id or nil
    }
    self:print_line("[Client] Established E2EE session with @" .. recipient .. " (X3DH + Double Ratchet).", true)
    return true
end

-- Request the recipient's bundle from the server and establish a session.
function ChatClient:ensure_session(recipient)
    if self.sessions[recipient] then return true end

    if not self:send_raw({ type = "prekey_request", recipient = recipient }) then
        return false
    end

    while true do
        local line, lerr = self:read_line(3)
        if not line then
            self:print_line("[Error] Timed out waiting for prekey bundle of @" .. recipient ..
                " (" .. tostring(lerr) .. ").", true)
            return false
        end
        local ok, pkt = pcall(json.decode, line)
        if ok and type(pkt) == "table" then
            if pkt.type == "prekey_bundle" and pkt.recipient == recipient then
                return self:establish_initiator(recipient, pkt.bundle)
            elseif pkt.type == "error" then
                self:handle_packet(pkt)
                return false
            else
                self:handle_packet(pkt) -- system/roster/messages that arrived meanwhile
            end
        end
        if not self.running then return false end
    end
end

function ChatClient:send_message(recipient, message)
    if recipient == self.username then
        self:print_line("[Error] That's you (" .. self.username .. ").")
        return
    end
    if not self:ensure_session(recipient) then return end

    local ratchet = self.sessions[recipient]
    local ad = self.crypto.identity_key.public .. (self.peer_iks[recipient] or "")
    local ok, enc = pcall(ratchet.encrypt, ratchet, message, ad)
    if not ok or not enc then
        self:print_line("[Error] Encryption failed for @" .. recipient .. ": " .. tostring(enc), true)
        return
    end

    local payload = { header = enc.header, nonce = enc.nonce, ct = enc.ct, tag = enc.tag }
    local x = self.x3dh_headers[recipient]
    if x then
        payload.x3dh = x
        self.x3dh_headers[recipient] = nil -- only on the first message
    end

    if self:send_raw({ type = "message", recipient = recipient, payload = payload }) then
        self:print_line("[You → @" .. recipient .. "] " .. message)
    end
end

function ChatClient:send_global(text)
    local members = {}
    for _, m in ipairs(self.roster) do
        if m ~= self.username then members[#members + 1] = m end
    end
    if #members == 0 then
        self:print_line("[Client] Nobody else is online right now.")
        return
    end

    local items, failed = {}, {}
    for _, m in ipairs(members) do
        if self:ensure_session(m) then
            local ad = self.crypto.identity_key.public .. (self.peer_iks[m] or "")
            local ok, enc = pcall(self.sessions[m].encrypt, self.sessions[m], text, ad)
            if ok and enc then
                local payload = { header = enc.header, nonce = enc.nonce, ct = enc.ct, tag = enc.tag }
                local x = self.x3dh_headers[m]
                if x then
                    payload.x3dh = x
                    self.x3dh_headers[m] = nil
                end
                items[#items + 1] = { to = m, payload = payload }
            else
                failed[#failed + 1] = m
            end
        else
            failed[#failed + 1] = m
        end
    end

    if #items == 0 then
        self:print_line("[Error] Global message could not be delivered to anyone.")
        return
    end
    if self:send_raw({ type = "global", items = items }) then
        self:print_line("[You → @all] " .. text)
        if #failed > 0 then
            self:print_line("[Client] Not delivered to: @" .. table.concat(failed, ", @"))
        end
    end
end

-- ---------------------------------------------------------------------------
-- Receiving
-- ---------------------------------------------------------------------------

function ChatClient:handle_packet(pkt)
    if pkt.type == "message" then
        self:handle_incoming(pkt)
    elseif pkt.type == "system" then
        self:print_line("[Global] " .. tostring(pkt.text), true)
    elseif pkt.type == "roster" then
        self.roster = pkt.members or {}
    elseif pkt.type == "error" then
        local code = tostring(pkt.code or "")
        if code == "user_offline" then
            self:print_line("[Error] @" .. tostring(pkt.detail) .. " is not online right now.", true)
        elseif code == "unknown_user" then
            self:print_line("[Error] Unknown user: @" .. tostring(pkt.detail), true)
        elseif code == "bad_packet" then
            self:print_line("[Error] Server rejected a packet (" .. tostring(pkt.detail) .. ").", true)
        else
            self:print_line("[Error] Server error: " .. code, true)
        end
    end
    -- prekey_bundle frames are consumed synchronously by ensure_session()
end

function ChatClient:handle_incoming(pkt)
    local sender = tostring(pkt.sender or "?")
    local payload = pkt.payload
    if type(payload) ~= "table" then return end

    local ratchet = self.sessions[sender]
    if not ratchet then
        -- First inbound message: answer the initiator's X3DH
        local x = payload.x3dh
        if type(x) ~= "table" or type(x.ik) ~= "string" or type(x.ek) ~= "string" then
            self:print_line("[Error] Cannot decrypt message from @" .. sender ..
                " (no session and no X3DH block).", true)
            return
        end
        local opk_priv = (x.opk_id and self.crypto:get_opk_priv(tonumber(x.opk_id))) or nil
        local ok, sk = pcall(self.crypto.x3dh_receiver, self.crypto,
            self.crypto.identity_key.private, self.crypto.signed_prekey.private,
            opk_priv, tostring(x.ik), tostring(x.ek))
        if not ok or not sk then
            self:print_line("[Error] X3DH (receiver) failed for @" .. sender .. ": " .. tostring(sk), true)
            return
        end
        local rok, r = pcall(double_ratchet.new, sk, false, nil, self.crypto.signed_prekey.private)
        if not rok or not r then
            self:print_line("[Error] Ratchet init failed for @" .. sender .. ": " .. tostring(r), true)
            return
        end
        ratchet = r
        self.sessions[sender] = ratchet
        self.peer_iks[sender] = tostring(x.ik)
        self:print_line("[Client] Established E2EE session with @" .. sender .. " (inbound X3DH).", true)
    end

    local ad = (self.peer_iks[sender] or "") .. self.crypto.identity_key.public
    local ok2, pt = pcall(ratchet.decrypt, ratchet, payload, ad)

    if (not ok2 or not pt) and type(payload.x3dh) == "table" then
        -- Session collision (both sides initiated simultaneously): rebuild a
        -- receiver session from the sender's X3DH block and retry. The DH
        -- ratchet re-converges both sides on the next exchange.
        local x = payload.x3dh
        if type(x.ik) == "string" and type(x.ek) == "string" then
            local opk_priv = (x.opk_id and self.crypto:get_opk_priv(tonumber(x.opk_id))) or nil
            local ok3, sk = pcall(self.crypto.x3dh_receiver, self.crypto,
                self.crypto.identity_key.private, self.crypto.signed_prekey.private,
                opk_priv, tostring(x.ik), tostring(x.ek))
            if ok3 and sk then
                local rok, r = pcall(double_ratchet.new, sk, false, nil, self.crypto.signed_prekey.private)
                if rok and r then
                    self.sessions[sender] = r
                    self.peer_iks[sender] = tostring(x.ik)
                    ok2, pt = pcall(r.decrypt, r, payload, tostring(x.ik) .. self.crypto.identity_key.public)
                end
            end
        end
    end

    if ok2 and pt then
        self:print_line("[@" .. sender .. "] " .. pt, true)
    else
        self:print_line("[Error] Decryption failed for a message from @" .. sender ..
            (ok2 and " (authentication)" or ": " .. tostring(pt)), true)
    end
end

-- ---------------------------------------------------------------------------
-- Interactive chat loop (poll on stdin + socket)
-- ---------------------------------------------------------------------------

-- Show the human-comparable fingerprint of an identity key.
-- No argument: our own fingerprint. With @user: the peer's IK fingerprint,
-- available once an E2EE session exists (peer IK is pinned at session setup).
function ChatClient:show_fingerprint(user)
    if not user then
        self:print_line("[Fingerprint] @" .. self.username .. " (you): " ..
            crypto_manager.fingerprint(self.crypto.identity_key.public))
        return
    end
    local ik = self.peer_iks[user]
    if not ik then
        self:print_line("[Error] No E2EE session with @" .. user ..
            " yet — fingerprints are available after the first message exchange.", true)
        return
    end
    self:print_line("[Fingerprint] @" .. user .. ": " .. crypto_manager.fingerprint(ik))
    self:print_line("[Fingerprint] Compare out-of-band (in person or voice) to rule out a MITM.", true)
end

function ChatClient:process_input(line)
    line = line:match("^%s*(.-)%s*$")
    if line == "" then return end

    if line == "exit" or line == "/quit" then
        self:send_raw({ type = "bye" })
        self.running = false
        return
    elseif line == "/help" then
        self:print_line("Commands: plain text = global room | @user msg = direct message | /who | /fingerprint [@user] | /help | exit")
        return
    elseif line == "/who" then
        if #self.roster == 0 then
            self:print_line("[Online] (nobody)")
        else
            self:print_line("[Online] @" .. table.concat(self.roster, " @"))
        end
        return
    elseif line == "/fingerprint" or line:match("^/fingerprint%s+%S+") then
        self:show_fingerprint(line:match("^/fingerprint%s+@?(%S+)"))
        return
    end

    local recipient, msg = line:match("^@(%S+)%s+(.+)$")
    if recipient then
        self:send_message(recipient, msg)
    else
        self:send_global(line)
    end
end

function ChatClient:start_chat_loop()
    print("\n--- Chat Active (global room) ---")
    print("Plain text          -> global room (E2EE per member)")
    print("@username message   -> direct message")
    print("/who /fingerprint /help exit -> roster, fingerprints, help, quit\n")

    local fds = ffi.new("pollfd_t[2]")
    fds[0].fd = 0 -- stdin
    fds[0].events = POLLIN
    fds[1].events = POLLIN

    io.write("[" .. self.username .. "]> ")
    io.flush()

    while self.running do
        -- Dispatch frames stranded in rbuf (e.g. read during handshake)
        local pok, perr = self:process_rbuf_lines()
        if not pok then
            self:print_line("[Client] Disconnected from server (" .. tostring(perr) .. ").", true)
            self.running = false
            break
        end

        fds[0].revents = 0
        fds[1].revents = 0
        fds[1].fd = self.sock and self.sock:getfd() or -1

        local n = ffi.C.poll(fds, 2, 200)
        if n > 0 then
            -- Socket readable (or hung up)?
            if bit.band(fds[1].revents, POLLIN) ~= 0 or bit.band(fds[1].revents, POLLHUP) ~= 0 then
                local ok, err = self:try_read_available()
                if not ok then
                    self:print_line("[Client] Disconnected from server (" .. tostring(err) .. ").", true)
                    self.running = false
                    break
                end
            end
            -- Stdin readable (a complete line is buffered)?
            if self.running and bit.band(fds[0].revents, POLLIN) ~= 0 then
                local line = io.read()
                if not line then
                    self.running = false -- EOF
                else
                    self:process_input(line)
                end
            end
        end
    end

    if self.sock then
        pcall(function() self.sock:close() end)
        self.sock = nil
    end
    print("Goodbye.")
end

return ChatClient
