#!/bin/sh

CONFIG_PATH="/etc/upbx.conf"
UPBXBIN="/usr/bin/upbx"

if [ -f "$CONFIG_PATH" ]; then
    echo "Using mounted config: $CONFIG_PATH"
else
    echo "Generating config from environment variables..."

    {
        echo "[upbx]"

        if [ -n "$SIP_ADDRESS" ]; then
            echo "address = $SIP_ADDRESS"
        else
            echo "address = :5060"
        fi

        echo "daemonize = 0"
        echo "data_dir = /var/lib/upbx"

        if [ -n "$RTPPROXY" ]; then
            echo "$RTPPROXY" | tr ',' '\n' | while read -r proxy; do
                echo "rtpproxy = $proxy"
            done
        fi

        if [ -n "$EMERGENCY" ]; then
            echo "$EMERGENCY" | tr ',' '\n' | while read -r num; do
                echo "emergency = $num"
            done
        fi

        env | grep -E '^GROUP_' | sort | while read -r line; do
            key="${line%%=*}"
            value="${line#*=}"
            group="${key#GROUP_}"
            group="${group%%_*}"
            echo "[group:$group]"
            if [ "$group" = "ALLOW_OUTGOING" ] || [ "$group" = "ALLOW_INCOMING" ]; then
                continue
            fi
            echo "allow_outgoing_cross_group = true"
            echo "allow_incoming_cross_group = true"
        done

        for var in $(env | grep -E '^EXT_[0-9]' | cut -d= -f1 | sort); do
            ext="${var#EXT_}"
            secret_env="EXT_${ext}"
            secret="$(eval echo \$${var})"
            echo "[ext:$ext]"
            echo "secret = $secret"
        done

        if [ -n "$TRUNK_NAME" ] && [ -n "$TRUNK_URL" ]; then
            echo "[trunk:$TRUNK_NAME]"
            echo "address = $TRUNK_URL"
            if [ -n "$TRUNK_DID" ]; then
                echo "$TRUNK_DID" | tr ',' '\n' | while read -r did; do
                    echo "did = $did"
                done
            fi
            if [ -n "$TRUNK_CID" ]; then
                echo "cid = $TRUNK_CID"
            fi
            if [ -n "$TRUNK_GROUP" ]; then
                echo "group = $TRUNK_GROUP"
            fi
        fi

    } > "$CONFIG_PATH"

    echo "Generated config:"
    cat "$CONFIG_PATH"
fi

CMD="${UPBXBIN}"

if [ -n "$LOG_LEVEL" ]; then
    CMD="${CMD} --verbosity ${LOG_LEVEL}"
fi

CMD="${CMD} daemon"

exec ${CMD}
