-- plugins/logger.lua - Sample plugin: logs core lifecycle events.
-- Server-scoped: loaded only by src/server_main.lua via load_dir().

return {
    name = "EventLogger",
    version = "1.0",
    scope = "server",

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
