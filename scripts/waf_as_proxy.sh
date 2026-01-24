#!/bin/sh
set -e

cargo build
BIN=target/debug/fantasma_cero
if ! getcap "$BIN" | grep -q cap_net_bind_service; then
    sudo setcap 'cap_net_bind_service=+ep' "$BIN"
fi

exec "$BIN" --port 80
