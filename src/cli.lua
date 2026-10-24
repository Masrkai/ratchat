-- cli.lua - Shared CLI helpers for the server/client entrypoints.
--
-- Usage text is entrypoint-specific and lives in server_main.lua /
-- client_main.lua; this module only holds the parsing and prompting logic
-- both of them need.

local cli = {}

function cli.valid_username(s)
    return type(s) == "string" and #s >= 1 and #s <= 16 and s:match("^[%w_]+$") ~= nil
end

-- Parses --host/--port/--name/--logs/--logfile/-h from argv. `mode` ("s"/"c")
-- is not accepted here: each entrypoint is single-purpose.
-- Returns opts table, or nil + error message on bad input.
function cli.parse_args(argv)
    local opts = { host = nil, port = nil, name = nil, logs = nil, logfile = nil }
    local i = 1
    while i <= #argv do
        local a = argv[i]
        if a == "--host" then
            i = i + 1
            if not argv[i] then return nil, "--host expects a value" end
            opts.host = argv[i]
        elseif a == "--port" then
            i = i + 1
            opts.port = tonumber(argv[i])
            if not opts.port or opts.port < 1 or opts.port > 65535 then
                return nil, "--port expects a number between 1 and 65535"
            end
        elseif a == "--name" then
            i = i + 1
            if not argv[i] then return nil, "--name expects a value" end
            opts.name = argv[i]
        elseif a == "--logs" then
            opts.logs = true
        elseif a == "--logfile" then
            i = i + 1
            if not argv[i] then return nil, "--logfile expects a file path" end
            opts.logfile = argv[i]
        elseif a == "--help" or a == "-h" then
            opts.help = true
        else
            return nil, "unknown argument: " .. tostring(a) .. " (try --help)"
        end
        i = i + 1
    end
    return opts
end

-- Prompts until a valid username is entered. Returns nil on EOF.
function cli.prompt_username(label)
    while true do
        io.write(label)
        io.flush()
        local input = io.read()
        if not input then return nil end -- EOF
        input = input:match("^%s*(.-)%s*$")
        if cli.valid_username(input) then
            return input
        end
        print("[Error] Username must be 1-16 letters, digits or underscores.")
    end
end

return cli
