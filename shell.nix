{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    luajit
    luarocks
    openssl
    pkg-config
    gcc
    luajitPackages.luasocket
    luajitPackages.lua-cjson
  ];

  shellHook = ''
    echo "=== Lua E2EE Chat Development Environment ==="
    echo "LuaJIT: $(luajit -v)"
    echo "OpenSSL: $(openssl version)"

    # Ensure LuaJIT FFI can locate libcrypto at runtime
    export LD_LIBRARY_PATH="${pkgs.openssl.out}/lib:$LD_LIBRARY_PATH"
  '';
}
