#!/bin/sh

# ── MQTT Admin User Configuration (runs first, before mosquitto starts) ─────────────
MQTT_ADMIN_USER="${MQTT_USERNAME:-admin}"
MQTT_ADMIN_PASS="${MQTT_PASSWORD:-2UbhHYRw}"
DEFAULT_MQTT_USER="admin"
DEFAULT_MQTT_PASS="2UbhHYRw"

echo "[BunkerM] MQTT credentials: user=$MQTT_ADMIN_USER"

# Generate password hash
TEMP_PASSWD_FILE="/tmp/mqtt_admin_passwd"
touch "$TEMP_PASSWD_FILE"
chmod 600 "$TEMP_PASSWD_FILE"
mosquitto_passwd -H sha512-pbkdf2 -b "$TEMP_PASSWD_FILE" "$MQTT_ADMIN_USER" "$MQTT_ADMIN_PASS" 2>/dev/null
PASSWD_HASH=$(grep "^$MQTT_ADMIN_USER:" "$TEMP_PASSWD_FILE" | cut -d: -f2)
rm -f "$TEMP_PASSWD_FILE"

if [ -z "$PASSWD_HASH" ]; then
    echo "[BunkerM] Warning: Could not generate password hash"
else
    # Format is: $7$101$<salt>$<hash>
    # With -F'$': $1="", $2="7", $3="101", $4=<salt>, $5=<hash>
    SALT=$(echo "$PASSWD_HASH" | awk -F'$' '{print $4}')
    HASH=$(echo "$PASSWD_HASH" | awk -F'$' '{print $5}')
    echo "[BunkerM] Generated password hash for user: $MQTT_ADMIN_USER"
fi
# ──────────────────────────────────────────────────────────────────────────────

# ── Bind-mount safety ──────────────────────────────────────────────────────────
# When users replace /etc/mosquitto or /var/lib/mosquitto with a bind mount,
# the host directory wins and wipes the files baked into the image. Restore
# them from /defaults/ if missing. Named-volume deployments are unaffected
# because the files already exist and these checks are skipped.
if [ ! -f /etc/mosquitto/mosquitto.conf ]; then
    echo "[BunkerM] mosquitto.conf missing — restoring default"
    mkdir -p /etc/mosquitto/conf.d
    cp /defaults/mosquitto/mosquitto.conf /etc/mosquitto/mosquitto.conf
    chmod 644 /etc/mosquitto/mosquitto.conf
fi
if [ ! -d /etc/mosquitto/conf.d ]; then
    mkdir -p /etc/mosquitto/conf.d
fi
cp -n /defaults/mosquitto/conf.d/. /etc/mosquitto/conf.d/ 2>/dev/null || true

# Restore or initialize dynamic-security.json
if [ ! -f /var/lib/mosquitto/dynamic-security.json ]; then
    echo "[BunkerM] dynamic-security.json missing — creating with configured credentials"
    mkdir -p /var/lib/mosquitto
    if [ -n "$HASH" ] && [ -n "$SALT" ]; then
        python3 << EOFPY
import json

admin_user = "$MQTT_ADMIN_USER"
password_hash = "$HASH"
salt = "$SALT"

data = {
    "defaultACLAccess": {
        "publishClientSend": True,
        "publishClientReceive": True,
        "subscribe": True,
        "unsubscribe": True
    },
    "clients": [{
        "username": admin_user,
        "textname": "Dynsec admin user",
        "roles": [{"rolename": "admin"}],
        "password": password_hash,
        "salt": salt,
        "iterations": 101
    }],
    "groups": [],
    "roles": [{
        "rolename": "admin",
        "acls": [
            {"acltype": "publishClientSend", "topic": "$CONTROL/dynamic-security/#", "priority": 0, "allow": True},
            {"acltype": "publishClientReceive", "topic": "$CONTROL/dynamic-security/#", "priority": 0, "allow": True},
            {"acltype": "publishClientReceive", "topic": "$SYS/#", "priority": 0, "allow": True},
            {"acltype": "publishClientReceive", "topic": "#", "priority": 0, "allow": True},
            {"acltype": "subscribePattern", "topic": "#", "priority": 0, "allow": True},
            {"acltype": "subscribePattern", "topic": "$CONTROL/dynamic-security/#", "priority": 0, "allow": True},
            {"acltype": "subscribePattern", "topic": "$SYS/#", "priority": 0, "allow": True},
            {"acltype": "unsubscribePattern", "topic": "#", "priority": 0, "allow": True}
        ]
    }]
}

with open("/var/lib/mosquitto/dynamic-security.json", "w") as f:
    json.dump(data, f, indent=4)
print(f"[BunkerM] Created dynamic-security.json with user: {admin_user}")
EOFPY
    else
        cp /defaults/mosquitto_data/dynamic-security.json /var/lib/mosquitto/dynamic-security.json
    fi
    chown mosquitto:mosquitto /var/lib/mosquitto/dynamic-security.json
    chmod 664 /var/lib/mosquitto/dynamic-security.json
else
    # File exists - check if credentials need updating
    if [ -n "$HASH" ] && [ -n "$SALT" ]; then
        echo "[BunkerM] Updating dynamic-security.json with configured credentials"
        python3 << EOFPY
import json

config_path = "/var/lib/mosquitto/dynamic-security.json"
admin_user = "$MQTT_ADMIN_USER"
password_hash = "$HASH"
salt = "$SALT"

try:
    with open(config_path, 'r') as f:
        data = json.load(f)
    
    for client in data.get('clients', []):
        roles = client.get('roles', [])
        role_names = [r.get('rolename', '') for r in roles]
        if 'admin' in role_names:
            client['username'] = admin_user
            client['password'] = password_hash
            client['salt'] = salt
            client['iterations'] = 101
            print(f"[BunkerM] Updated admin user to: {admin_user}")
            break
    else:
        data['clients'].insert(0, {
            'username': admin_user,
            'textname': 'Dynsec admin user',
            'roles': [{'rolename': 'admin'}],
            'password': password_hash,
            'salt': salt,
            'iterations': 101
        })
        print(f"[BunkerM] Added admin user: {admin_user}")
    
    with open(config_path, 'w') as f:
        json.dump(data, f, indent=4)
    print("[BunkerM] Dynamic security config updated")
except Exception as e:
    print(f"[BunkerM] Error updating config: {e}")
EOFPY
    fi
fi
# ──────────────────────────────────────────────────────────────────────────────

# Create required directories and files
mkdir -p /var/log/mosquitto /var/log/supervisor /var/log/nginx /var/log/api /nextjs/data
touch /var/log/mosquitto/mosquitto.log
touch /var/log/mosquitto/mosquitto.err.log
touch /var/log/api/api_activity.log
touch /etc/mosquitto/mosquitto_passwd
chown mosquitto:mosquitto /etc/mosquitto/mosquitto_passwd
chmod 664 /etc/mosquitto/mosquitto_passwd
chown -R mosquitto:root /var/log/mosquitto
chmod -R 644 /var/log/mosquitto
chmod 755 /var/log/mosquitto
chmod -R 755 /var/log/supervisor
chmod -R 755 /var/log/api
mkdir -p /nextjs/data && chmod 755 /nextjs/data

# ── API key bootstrap ──────────────────────────────────────────────────────────
KEY_FILE="/nextjs/data/.api_key"
DEFAULT_KEY="default_api_key_replace_in_production"

if [ -n "$API_KEY" ] && [ "$API_KEY" != "$DEFAULT_KEY" ]; then
    echo "$API_KEY" > "$KEY_FILE"
    chmod 600 "$KEY_FILE"
    echo "[BunkerM] Using API key from environment variable."
elif [ -f "$KEY_FILE" ] && [ -s "$KEY_FILE" ]; then
    export API_KEY=$(cat "$KEY_FILE")
    echo "[BunkerM] Loaded existing API key from persistent storage."
else
    export API_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    echo "$API_KEY" > "$KEY_FILE"
    chmod 600 "$KEY_FILE"
    echo "[BunkerM] Generated new API key and saved to persistent storage."
fi
# ──────────────────────────────────────────────────────────────────────────────

pkill nginx 2>/dev/null || true
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
