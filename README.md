# UPBX

A standalone minimalist SIP PBX daemon: extension and trunk registration, call routing

**Inspired by [siproxd](https://github.com/hb9xar/siproxd)** — UPBX’s design (built-in RTP relay, SIP proxy behavior, and plugin hooks) draws on siproxd (though heavily modified).

---

## Building

Requirements: [dep](https://github.com/finwo/dep), C compiler.

```bash
make
```

The binary is `upbx`.

---

## Running the daemon

The main entry point is the **daemon** command. You must pass a config file.

```bash
# Foreground (default)
./upbx daemon -f /etc/upbx.conf

# Background (daemonize)
./upbx daemon -f /etc/upbx.conf -d

# Force foreground even if config has daemonize=1
./upbx daemon -f /etc/upbx.conf -D
```

| Option | Short | Description |
|--------|--------|--------------|
| `--config <path>` | `-f` | Config file path (required for daemon). |
| `--daemonize` | `-d` | Run in background (double fork, detach from terminal). |
| `--no-daemonize` | `-D` | Force foreground; overrides `daemonize=1` in config. |

Daemonize behaviour:

- By default the daemon runs in the **foreground**.
- It goes to the **background** only if `daemonize=1` is set in `[upbx]` **or** you pass `-d`/`--daemonize`.
- `-D`/`--no-daemonize` always forces foreground.

After starting, the daemon loads config, starts the built-in RTP relay, spawns any configured plugins, binds the SIP UDP socket, and handles REGISTER (extensions and trunk registration) and INVITE (routing). Logging goes to stderr (and optionally to a file if you use global `--log`).

---

## Example configuration

Full example with every option listed (optional ones commented). Minimal setups can omit the commented lines.

```ini
[upbx]
listen = 0.0.0.0:5060
rtp_ports = 10000-20000
daemonize = 0
# locality = 4
# emergency = 911
# emergency = 112

[plugin:myplugin]
exec = /usr/bin/my-plugin-binary

[trunk:mycarrier]
host = sip.example.com
port = 5060
username = myuser
password = mypass
did = 15559876543
# did = 15551234567
cid = 15559876543
# cid_name = My Company
# pattern = ^00(.*)
# replace = \1
# pattern = ^0
# replace = 31
# overflow_timeout = 30
# overflow_strategy = none
# overflow_target =
# user_agent = upbx/1.0
# group = 1234

[ext:100]
# name = Front desk
secret = my-secret
```

### `[upbx]`

There is **no** `advertise` (or similar) option. The address used in Via/SDP is learned per extension from that extension's REGISTER; `listen` is used as fallback. Do not add an advertise option.

| Option | Description |
|--------|-------------|
| `listen` | SIP UDP bind address (e.g. `0.0.0.0:5060` or `192.168.1.1:5060`). Fallback for Via/SDP when not yet learned from REGISTER. |
| `rtp_ports` | Port range for the built-in RTP relay, as `low-high` (e.g. `10000-20000`). Default 10000–20000. |
| `daemonize` | `1` = run in background when started without `-d`/`-D`; `0` = foreground. |
| `locality` | Number of digits for short-dial / group routing. When set, an extension’s trunk can be chosen by **group**: if the extension number has more than `locality` digits and its prefix matches a trunk’s `group`, that trunk is used for outgoing calls (see `[trunk]` `group`). `0` = disabled. |
| `emergency` | Emergency number(s); can repeat. Used when routing emergency calls from extensions. |

### `[plugin:name]`

| Option | Description |
|--------|-------------|
| `exec` | Command to run (via `sh -c`). Process communicates over stdio using a RESP-style protocol; discovery via `COMMAND`. See [Plugin events](#plugin-events) for available events. |

### `[trunk:name]`

| Option | Description |
|--------|-------------|
| `host` | Upstream SIP server hostname or IP. |
| `port` | Upstream SIP port (default 5060 if omitted). |
| `username` | Username for trunk registration. |
| `password` | Password for trunk registration. |
| `did` | Incoming DID(s); can repeat. Incoming calls to this DID are forked to extensions registered on this trunk. |
| `cid` | Outgoing caller ID number. |
| `cid_name` | Optional caller ID display name. |
| `pattern` | Regex pattern for number rewriting (use with `replace`). |
| `replace` | Replacement string for the last `pattern` (applied in order). |
| `overflow_timeout` | Seconds before overflow behaviour; `0` = disabled. |
| `overflow_strategy` | `none`, `busy`, `include`, or `redirect`. |
| `overflow_target` | Target number for `overflow_strategy = include` or `redirect`. |
| `user_agent` | Custom User-Agent for trunk registration. |
| `group` | **Group prefix for locality.** When `[upbx]` `locality` is set, extensions whose number starts with this prefix and has at least `len(group) + locality` digits use this trunk for outgoing. E.g. `group = 1234`, `locality = 4`: extension `12341000` (8 digits, prefix 1234) uses this trunk. |

### `[ext:number]`

| Option | Description |
|--------|-------------|
| `name` | Optional display name. |
| `secret` | Password for extension digest auth. |

With this, extensions register as `<number>@<trunk>` (or via your dial plan). Incoming calls to a DID go to all registered extensions on that trunk. Outgoing calls use the extension’s trunk (from `@trunk`, or from **locality/group** when `locality` and a trunk `group` match the extension number).

## Plugin events

| Event | When | Args / response |
|------|------|------------------|
| `EXTENSION.REGISTER` | Before accepting REGISTER | extension, trunk, from_user → DENY / ALLOW [custom] / continue |
| `EXTENSION.LIST` | At start and on registration change | 3 per ext: number, name, trunk (no secret) |
| `TRUNK.LIST` | At start and on registration change | 5 per trunk: name, group_prefix, dids, cid, extensions (no credentials) |
| `CALL.DIALOUT` | Outgoing call from extension (before emergency) | source_ext, source_trunk, destination, call_id → no-edit / REJECT [code] / ALLOW [target]; ignored if destination is emergency |
| `CALL.DIALIN` | Incoming call to DID | trunk, did, ext1, ext2, …, call_id → dont-care / REJECT [code] / ALTER ext… |
| `CALL.ANSWER` | When a call is picked up (dialin) | direction, call_id, source, destination (event; response ignored) |
| `CALL.HANGUP` | When a call is terminated | call_id, source, destination, duration_sec (event; response ignored) |