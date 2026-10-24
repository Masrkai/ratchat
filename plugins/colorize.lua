-- plugins/colorize.lua - ANSI colorizing of client display output.
--
-- Hooks the client's display filter ("display" event on the plugin manager,
-- invoked from ChatClient:print_line) and wraps lines in ANSI escape codes:
--   * [Error] / [Global] / [Client] / [Online] / [Fingerprint] / [You ...]
--     lines get fixed colors per tag
--   * incoming "[@sender] ..." lines get a deterministic per-sender color
--     (hashed username -> curated 256-color palette)
--
-- Colors are display-only: they never touch the wire or the crypto layer.
-- Disabled automatically when stdout is not a TTY or NO_COLOR is set;
-- force-enable with RATCHAT_COLOR=force (e.g. for piping into less -R).

local bit = require("bit")
local ffi = require("ffi")

ffi.cdef[[ int isatty(int fd); ]]

local Colorize = {
    name = "Colorize",
    version = "1.0",
    enabled = false,
}

local function stdout_is_tty()
    local ok, res = pcall(function() return ffi.C.isatty(1) == 1 end)
    return ok and res or false
end

-- Readable, distinct 256-color codes (bright cyan/green/yellow/orange/
-- magenta/blue family). Index by a username hash.
local PALETTE = { 51, 87, 118, 156, 190, 214, 201, 129, 75, 208, 46, 226 }

-- Deterministic small hash (djb2-style with rotate) so a peer keeps the
-- same color for the whole session.
local function hash_name(s)
    local h = 5381
    for i = 1, #s do
        h = bit.band(bit.rol(h, 5) + s:byte(i), 0x7fffffff)
    end
    return h
end

local function sender_color(name)
    return PALETTE[(hash_name(name) % #PALETTE) + 1]
end

-- { pattern, ANSI code } — first match wins. Checked after the [@sender] rule.
local TAG_COLORS = {
    { "^%[Error%]", "31" },        -- red
    { "^%[Global%]", "33" },       -- yellow
    { "^%[Client%]", "34" },       -- blue
    { "^%[Online%]", "36" },       -- cyan
    { "^%[Fingerprint%]", "35" },  -- magenta
    { "^%[You", "32" },            -- green (own messages)
}

local function wrap(code, text)
    return "\27[" .. code .. "m" .. text .. "\27[0m"
end

-- Transform one display line. Returns text unchanged when disabled.
-- Exposed for tests.
function Colorize.colorize(text, enabled)
    if not enabled or type(text) ~= "string" or #text == 0 then
        return text
    end

    -- Incoming DM: "[@sender] message"
    local sender = text:match("^%[@([%w_]+)%]")
    if sender then
        return wrap("38;5;" .. sender_color(sender), text)
    end

    for _, rule in ipairs(TAG_COLORS) do
        if text:match(rule[1]) then
            return wrap(rule[2], text)
        end
    end
    return text
end

function Colorize.on_load(manager)
    local forced = os.getenv("RATCHAT_COLOR") == "force"
    Colorize.enabled = forced or (os.getenv("NO_COLOR") == nil and stdout_is_tty())

    manager:on("display", function(text)
        return Colorize.colorize(text, Colorize.enabled)
    end)
end

return Colorize
