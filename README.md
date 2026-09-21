# ng1FileUploader

`ng1FileUploader` batch-uploads PCAP files to one or more nGeniusONE servers
and registers them in **Packet Analysis → File Analysis**.

Uploading to `UploadFile.jsp` only copies the file bytes. This tool also
performs the required PA application-session metadata insertion (opcode 101)
and verifies the resulting File Analysis entries with opcode 100.

## Features

- Reads nGeniusONE targets from `hosts.txt`
- Uploads every `.pcap`, `.pcapng`, and `.cap` file in `pcaps/`
- Supports bare hosts, explicit ports, and complete HTTPS URLs
- Prompts securely for the nGeniusONE GUI/API password
- Detects the PA server's real identity with opcode 120
  - Handles cloud systems whose public hostname differs from their private PA address
  - Maps Standalone, Local, and Global server types correctly
- Skips files already registered with the same name and size
- Recovers when file bytes exist but File Analysis metadata is missing
- Verifies every filename and byte count after registration
- Continues through the host list and returns a nonzero status if any host fails
- Logs out and securely removes temporary session-cookie files

## Requirements

- Bash 4 or newer
- `curl`
- `jq`
- `openssl`
- GNU/Coreutils tools: `od`, `stat`, `sort`, and `shred`
- Network access to each nGeniusONE web console
- An nGeniusONE account allowed to use Packet Analysis

The password is the **nGeniusONE GUI/API password**, not the Linux root
password.

## Installation

```bash
git clone https://github.com/fcp999/ng1FileUploader.git
cd ng1FileUploader
chmod 750 upload.sh
cp hosts.txt.example hosts.txt
mkdir -p pcaps
```

## Configure targets

Put one server on each line of `hosts.txt`. Blank lines and comments are
ignored.

```text
# Bare hosts default to HTTPS port 8443
192.0.2.10

# Explicit URLs preserve their specified port
https://ng1.example.net:8443

# Cloud consoles commonly use HTTPS port 443
https://example.netscout.cloud
```

## Add captures

Copy capture files into `pcaps/`:

```bash
cp /path/to/captures/*.pcap* pcaps/
```

PCAP files and `hosts.txt` are excluded from Git by default.

## Run

The default username is `administrator`. The script prompts once for its
nGeniusONE password:

```bash
./upload.sh
```

Specify different input paths:

```bash
./upload.sh /path/to/hosts.txt /path/to/pcaps
```

Use a different nGeniusONE username:

```bash
NG1_USER=analyst ./upload.sh
```

For unattended execution, use a protected password file:

```bash
chmod 600 /secure/path/ng1-password
NG1_PASSWORD_FILE=/secure/path/ng1-password ./upload.sh
```

`NG1_PASSWORD` is also supported, but a prompt or protected password file is
preferable because environment variables can be exposed to other privileged
processes.

## TLS behavior

The default accommodates appliances with self-signed certificates by using
curl's insecure TLS mode. To require normal certificate validation:

```bash
NG1_VERIFY_TLS=1 ./upload.sh
```

## What the script does

For each host, the script:

1. Opens an encrypted nGeniusONE web session.
2. Creates a `PASERVICE_APPLICATION` session.
3. Requests opcode 120 to obtain the server's PA address and server type.
4. Requests opcode 100 to inventory existing File Analysis entries.
5. Uploads missing file bytes through `UploadFile.jsp`.
6. Inserts missing metadata with opcode 101.
7. Requests opcode 100 again and verifies every filename and byte count.
8. Closes the PA session, logs out, and destroys temporary authentication files.

## Existing and duplicate files

- **Same filename and size already registered:** skipped.
- **Same filename but different registered size:** reported as an error; the
  script does not overwrite it.
- **Bytes uploaded but metadata absent:** `UploadFile.jsp` returns `duplicate`;
  the script proceeds with opcode 101 to repair the missing File Analysis entry.

## Advanced environment variables

| Variable | Purpose | Default |
|---|---|---|
| `NG1_USER` | nGeniusONE GUI/API username | `administrator` |
| `NG1_PASSWORD_FILE` | File containing the password on its first line | Prompt |
| `NG1_PASSWORD` | Password supplied through the environment | Prompt |
| `NG1_VERIFY_TLS` | Set to `1` to validate server certificates | `0` |
| `NG1_SOURCE_LOCATION_TYPE` | Override the PA location type when necessary | Auto-detected |

Automatic source-location mappings are:

- Standalone → `1`
- Local → `2`
- Global → `3`

## Troubleshooting

### `Invalid Source_Server_IP`

Use the current version of the script. It obtains
`loggedInServerAddress` and `serverType` from opcode 120 rather than using the
hostname from `hosts.txt`.

### `mapfile: -d: invalid option`

Older Bash releases do not support `mapfile -d`. The current script uses a
portable null-delimited `read` loop instead.

### Authentication failure

Confirm that you are using the web-console/GUI password. Do not use the Linux
root password.

### File uploaded but not visible in File Analysis

Rerun the current script. It treats the existing byte upload as a duplicate and
retries the missing opcode-101 metadata registration.

## Exit codes

- `0`: every host and file verified successfully
- `1`: one or more hosts or files failed
- `2`: local configuration, dependency, or input error

## Security notes

- Do not commit `hosts.txt`, packet captures, password files, cookie jars, or
  environment files.
- Prefer `NG1_PASSWORD_FILE` with mode `600` for automation.
- Enable certificate validation where your nGeniusONE servers use trusted
  certificates.
