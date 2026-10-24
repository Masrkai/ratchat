-- plugins/logger.lua - Sample plugin: logs core lifecycle events.
-- Registered automatically by src/main.lua (safe to remove).

return {
    name = "EventLogger",
    version = "1.0",

    on_load = function(manager)
        manager:on("server_started", function(ip, port)
            print(string.format("[Plugin: EventLogger] Server started on %s:%d", ip, port))
        end)

        manager:on("client_joined", function(username)
            print(string.format("[Plugin: EventLogger] User joined: @%s", tostring(username)))
        end)

        manager:on("client_left", function(username)
            print(string.format("[Plugin: EventLogger] User left: @%s", tostring(username)))
        end)
    end
}
