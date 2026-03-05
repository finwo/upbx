#!/bin/sh

CONFIG_PATH="/etc/upbx.conf"

if [ -f "$CONFIG_PATH" ]; then
    echo "Using mounted config: $CONFIG_PATH"
else
    echo "Generating config from environment variables..."

    {
        echo "[upbx]"

        if [ -n "$SIP_ADDRESS" ]; then
            echo "$SIP_ADDRESS" | tr ',' '\n' | while read -r addr; do
                echo "address = $addr"
            done
        else
            echo "address = :5060"
        fi

        if [ -n "$UPBX_SECRET" ]; then
            echo "secret = $UPBX_SECRET"
        fi

        if [ -n "$RTPPROXY" ]; then
            echo "$RTPPROXY" | tr ',' '\n' | while read -r proxy; do
                echo "rtpproxy = $proxy"
            done
        fi

        if [ -n "$API_ADDRESS" ]; then
            echo "$API_ADDRESS" | tr ',' '\n' | while read -r addr; do
                echo "[api]"
                echo "address = $addr"
            done
        fi

        if [ -n "$API_ADMIN_USER" ] && [ -n "$API_ADMIN_PASS" ]; then
            echo "[api:$API_ADMIN_USER]"
            echo "permit = *"
            echo "secret = $API_ADMIN_PASS"
        fi
    } > "$CONFIG_PATH"

    echo "Generated config:"
    cat "$CONFIG_PATH"
fi

exec /usr/bin/upbx --config /etc/upbx.conf daemon --no-daemonize
