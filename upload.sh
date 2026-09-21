#!/usr/bin/env bash
set -Eeuo pipefail

# Upload every PCAP/PCAPNG in pcaps/ to every nGeniusONE host in hosts.txt,
# register each upload in Packet Analysis -> File Analysis, and verify it.
#
# Credentials are never accepted as command-line arguments:
#   export NG1_USER=administrator       # optional; this is the default
#   export NG1_PASSWORD='...'           # optional; otherwise prompted once
#
# Usage:
#   ./upload-pcaps-to-ng1.sh [hosts.txt] [pcaps-directory]

HOSTS_FILE=${1:-hosts.txt}
PCAP_DIR=${2:-pcaps}
NG1_USER=${NG1_USER:-administrator}
SOURCE_LOCATION_TYPE_OVERRIDE=${NG1_SOURCE_LOCATION_TYPE:-}

for tool in curl jq openssl od stat find sort shred; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'ERROR: required command not found: %s\n' "$tool" >&2
        exit 2
    }
done

[[ -r "$HOSTS_FILE" ]] || {
    printf 'ERROR: hosts file is missing or unreadable: %s\n' "$HOSTS_FILE" >&2
    exit 2
}
[[ -d "$PCAP_DIR" ]] || {
    printf 'ERROR: PCAP directory does not exist: %s\n' "$PCAP_DIR" >&2
    exit 2
}
[[ "$NG1_USER" =~ ^[A-Za-z0-9_.-]+$ ]] || {
    printf 'ERROR: NG1_USER contains unsupported characters\n' >&2
    exit 2
}
if [[ -n $SOURCE_LOCATION_TYPE_OVERRIDE && ! $SOURCE_LOCATION_TYPE_OVERRIDE =~ ^[0-9]+$ ]]; then
    printf 'ERROR: NG1_SOURCE_LOCATION_TYPE must be numeric\n' >&2
    exit 2
fi

if [[ -n ${NG1_PASSWORD_FILE:-} ]]; then
    [[ -r "$NG1_PASSWORD_FILE" ]] || {
        printf 'ERROR: NG1_PASSWORD_FILE is unreadable\n' >&2
        exit 2
    }
    IFS= read -r NG1_PASSWORD < "$NG1_PASSWORD_FILE"
elif [[ -z ${NG1_PASSWORD:-} ]]; then
    read -r -s -p "Password for ${NG1_USER}: " NG1_PASSWORD
    printf '\n'
fi
[[ -n "$NG1_PASSWORD" ]] || {
    printf 'ERROR: password is empty\n' >&2
    exit 2
}

if [[ ${NG1_VERIFY_TLS:-0} == 1 ]]; then
    CURL_TLS=()
else
    CURL_TLS=(-k)
fi

PCAP_FILES=()
while IFS= read -r -d '' file; do
    PCAP_FILES+=("$file")
done < <(
    find "$PCAP_DIR" -maxdepth 1 -type f \
        \( -iname '*.pcap' -o -iname '*.pcapng' -o -iname '*.cap' \) \
        -print0 | sort -z
)
[[ ${#PCAP_FILES[@]} -gt 0 ]] || {
    printf 'ERROR: no .pcap, .pcapng, or .cap files found in %s\n' "$PCAP_DIR" >&2
    exit 2
}

hex_bytes() {
    od -v -An -tx1 | tr -d ' \n'
}

aes_encrypt_hex() {
    local plaintext=$1 session_key=$2 key_hex iv_hex
    key_hex=$(printf '%s%s' "${session_key:0:16}" "${session_key:0:16}" | hex_bytes)
    iv_hex=$(printf '%s' 'ulFAiLTrKotxpnPV' | hex_bytes)
    printf '%s' "$plaintext" |
        openssl enc -aes-256-cbc -K "$key_hex" -iv "$iv_hex" 2>/dev/null |
        hex_bytes
}

normalize_base_url() {
    local value=${1%/}
    if [[ $value =~ ^https?:// ]]; then
        printf '%s' "$value"
    elif [[ $value == \[*\] ]]; then
        printf 'https://%s:8443' "$value"
    elif [[ $value == *:* ]]; then
        printf 'https://%s' "$value"
    else
        printf 'https://%s:8443' "$value"
    fi
}

source_server_from_url() {
    local value=${1#*://}
    value=${value%%/*}
    if [[ $value == \[*\]* ]]; then
        value=${value#\[}
        value=${value%%\]*}
    else
        value=${value%%:*}
    fi
    printf '%s' "$value"
}

trim_line() {
    local value=$1
    value=${value%%#*}
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

CURRENT_BASE=''
CURRENT_JAR=''
CURRENT_TMP=''
CURRENT_SMID=''
CURRENT_APPID=''

cleanup_current_host() {
    if [[ -n $CURRENT_BASE && -n $CURRENT_JAR && -r $CURRENT_JAR ]]; then
        if [[ -n $CURRENT_SMID && -n $CURRENT_APPID ]]; then
            curl -sS "${CURL_TLS[@]}" -b "$CURRENT_JAR" -X POST \
                "$CURRENT_BASE/common/InitSession.jsp" \
                --data-urlencode "killid=$CURRENT_APPID" \
                --data-urlencode "smid=$CURRENT_SMID" >/dev/null 2>&1 || true
        fi
        curl -sS "${CURL_TLS[@]}" -b "$CURRENT_JAR" \
            "$CURRENT_BASE/racommon/NSLogout.jsp" >/dev/null 2>&1 || true
    fi
    if [[ -n $CURRENT_TMP && -d $CURRENT_TMP ]]; then
        find "$CURRENT_TMP" -maxdepth 1 -type f -exec shred -u -- {} + 2>/dev/null || true
        rmdir "$CURRENT_TMP" 2>/dev/null || true
    fi
    CURRENT_BASE=''
    CURRENT_JAR=''
    CURRENT_TMP=''
    CURRENT_SMID=''
    CURRENT_APPID=''
}
trap cleanup_current_host EXIT

PA_SESSION_KEY=''
PA_REQUEST_ID=10001

pa_request() {
    local opcode=$1 data=$2 response_file=$3
    local request message raw attempt

    request=$(jq -cn \
        --argjson smid "$CURRENT_SMID" \
        --argjson session "$CURRENT_APPID" \
        --argjson opcode "$opcode" \
        --argjson request_id "$PA_REQUEST_ID" \
        --argjson submitted "$(date +%s%3N)" \
        --argjson data "$data" \
        '{smid:$smid,clientId:100,sessionId:$session,opCode:$opcode,
          data:$data,requestId:$request_id,submitTime:$submitted,endTime:0,
          handleResponse:null}') || return 1

    message="ver2_$(aes_encrypt_hex "$request" "$PA_SESSION_KEY")" || return 1
    curl -sS "${CURL_TLS[@]}" --max-time 30 \
        -b "$CURRENT_JAR" -c "$CURRENT_JAR" -X POST \
        "$CURRENT_BASE/common/SendMessage.jsp" \
        -H 'Content-Type: application/json; charset=utf-8' \
        -H 'NS-App-Session-Name: PASERVICE_APPLICATION' \
        --data-binary "$message" >/dev/null || return 1

    raw="$CURRENT_TMP/poll-${PA_REQUEST_ID}.json"
    : > "$response_file"
    for attempt in 1 2 3; do
        curl -sS "${CURL_TLS[@]}" --max-time 35 \
            -b "$CURRENT_JAR" -c "$CURRENT_JAR" -X POST \
            "$CURRENT_BASE/common/EventPoller.jsp" \
            --data-urlencode "smid=$CURRENT_SMID" > "$raw" || return 1

        if jq --argjson rid "$PA_REQUEST_ID" -c \
            'map(fromjson) | map(select(.requestId == $rid)) | .[0].msg // empty' \
            "$raw" > "$response_file" 2>/dev/null && [[ -s $response_file ]]; then
            PA_REQUEST_ID=$((PA_REQUEST_ID + 1))
            return 0
        fi
    done

    printf 'ERROR: no PA response for request %s\n' "$PA_REQUEST_ID" >&2
    return 1
}

upload_host() {
    local host_line=$1 host_label source_server server_type source_location_type
    local page login_body event_json app_json response_json upload_json
    local login_sid login_cipher smport existing insert_list
    local file name size extension format mime upload_status existing_size
    local added=0 skipped=0 failed=0

    cleanup_current_host
    CURRENT_BASE=$(normalize_base_url "$host_line")
    host_label=$(source_server_from_url "$CURRENT_BASE")
    CURRENT_TMP=$(mktemp -d)
    CURRENT_JAR="$CURRENT_TMP/cookies.txt"
    page="$CURRENT_TMP/login.html"
    login_body="$CURRENT_TMP/login-result.html"
    event_json="$CURRENT_TMP/event.json"
    app_json="$CURRENT_TMP/app.json"
    response_json="$CURRENT_TMP/response.json"
    upload_json="$CURRENT_TMP/upload.json"
    PA_REQUEST_ID=10001
    CURRENT_SMID=''
    CURRENT_APPID=''

    printf '\n[%s] Authenticating\n' "$host_label"
    curl -sS "${CURL_TLS[@]}" --max-time 30 -c "$CURRENT_JAR" \
        "$CURRENT_BASE/racommon/NSLogin.jsp?redirect=/paapp/PAHome.jsp" \
        -o "$page" || return 1

    login_sid=$(sed -n 's/.*data-session-id = \([^[:space:]]*\).*/\1/p' "$page" | head -1)
    [[ ${#login_sid} -ge 16 ]] || {
        printf '[%s] ERROR: login session ID not found\n' "$host_label" >&2
        return 1
    }
    login_cipher=$(aes_encrypt_hex "$NG1_PASSWORD" "$login_sid") || return 1

    curl -sS "${CURL_TLS[@]}" --max-time 30 \
        -b "$CURRENT_JAR" -c "$CURRENT_JAR" -o "$login_body" -X POST \
        "$CURRENT_BASE/racommon/NSLogin.jsp" \
        --data-urlencode 'mode=login' \
        --data-urlencode 'redirect=/paapp/PAHome.jsp' \
        --data-urlencode "username=$NG1_USER" \
        --data-urlencode "password=$login_cipher" \
        --data-urlencode "displayUsername=$NG1_USER" \
        --data-urlencode "displayPassword=$login_cipher" || return 1

    curl -sS "${CURL_TLS[@]}" --max-time 30 \
        -b "$CURRENT_JAR" -c "$CURRENT_JAR" -X POST \
        "$CURRENT_BASE/common/EventPollerInit.jsp" --data 'smid=0' \
        -o "$event_json" || return 1

    CURRENT_SMID=$(jq -er '.smid | select(. > 0)' "$event_json") || {
        printf '[%s] ERROR: authentication or EventPoller initialization failed\n' "$host_label" >&2
        return 1
    }
    smport=$(jq -er '.smport' "$event_json") || return 1
    PA_SESSION_KEY=$(jq -er '.sessionIdStr | select(length >= 16)' "$event_json") || return 1

    curl -sS "${CURL_TLS[@]}" --max-time 30 \
        -b "$CURRENT_JAR" -c "$CURRENT_JAR" -X POST \
        "$CURRENT_BASE/common/InitSession.jsp" \
        --data-urlencode 'type=PASERVICE_APPLICATION' \
        --data-urlencode "smid=$CURRENT_SMID" \
        --data-urlencode 'clientid=100' \
        --data-urlencode "smport=$smport" -o "$app_json" || return 1
    CURRENT_APPID=$(jq -er '.sessionId | select(. > 0)' "$app_json") || {
        printf '[%s] ERROR: PA application session initialization failed\n' "$host_label" >&2
        return 1
    }

    # The browser-visible hostname is not necessarily the PA server identity.
    # Cloud deployments commonly use a public DNS name while PA identifies the
    # logged-in server by its private address and Local/Global server type.
    pa_request 120 '{}' "$response_json" || return 1
    source_server=$(jq -er \
        '[.. | objects | .loggedInServerAddress? // empty][0] |
         select(type == "string" and length > 0)' "$response_json") || {
        printf '[%s] ERROR: opcode 120 did not return loggedInServerAddress\n' \
            "$host_label" >&2
        return 1
    }
    server_type=$(jq -er \
        '[.. | objects | .serverType? // empty][0] |
         select(type == "string" and length > 0)' "$response_json") || {
        printf '[%s] ERROR: opcode 120 did not return serverType\n' \
            "$host_label" >&2
        return 1
    }
    if [[ -n $SOURCE_LOCATION_TYPE_OVERRIDE ]]; then
        source_location_type=$SOURCE_LOCATION_TYPE_OVERRIDE
    else
        case ${server_type,,} in
            standalone) source_location_type=1 ;;
            local)      source_location_type=2 ;;
            global)     source_location_type=3 ;;
            *)
                printf '[%s] ERROR: unsupported PA serverType: %s\n' \
                    "$host_label" "$server_type" >&2
                return 1
                ;;
        esac
    fi
    printf '[%s] PA server identity: %s (%s, location type %s)\n' \
        "$host_label" "$source_server" "$server_type" "$source_location_type"

    pa_request 100 '{}' "$response_json" || return 1
    [[ $(jq -r '.Status // empty' "$response_json") == success ]] || {
        printf '[%s] ERROR: unable to read File Analysis inventory\n' "$host_label" >&2
        return 1
    }
    existing=$(jq -c '.Data.TraceFiles // []' "$response_json") || return 1
    insert_list='[]'

    for file in "${PCAP_FILES[@]}"; do
        name=${file##*/}
        size=$(stat -c %s "$file") || return 1
        extension=${name##*.}
        extension=${extension,,}
        if [[ $name == *$'\n'* || $name == *';'* ]]; then
            printf '[%s] ERROR: unsupported filename: %q\n' "$host_label" "$name" >&2
            failed=$((failed + 1))
            continue
        fi

        existing_size=$(jq -r --arg name "$name" \
            '[.[] | select(.Trace_File_Name == $name)][0].Total_Bytes // empty' \
            <<< "$existing") || return 1
        if [[ -n $existing_size ]]; then
            if [[ $existing_size == "$size" ]]; then
                printf '[%s] SKIP %s (already registered, %s bytes)\n' \
                    "$host_label" "$name" "$size"
                skipped=$((skipped + 1))
            else
                printf '[%s] ERROR %s exists with %s bytes; local file has %s bytes\n' \
                    "$host_label" "$name" "$existing_size" "$size" >&2
                failed=$((failed + 1))
            fi
            continue
        fi

        if [[ $extension == pcapng ]]; then
            format=2
        else
            format=1
        fi
        mime='application/vnd.tcpdump.pcap'

        printf '[%s] UPLOAD %s (%s bytes)\n' "$host_label" "$name" "$size"
        curl -sS "${CURL_TLS[@]}" --max-time 600 \
            -b "$CURRENT_JAR" -c "$CURRENT_JAR" -X POST \
            -F "${name}=@${file};type=${mime}" \
            "$CURRENT_BASE/paapp/UploadFile.jsp?overwrite=N&location=$NG1_USER" \
            -o "$upload_json" || {
                failed=$((failed + 1))
                continue
            }
        upload_status=$(jq -r '.status // empty' "$upload_json" 2>/dev/null || true)
        if [[ $upload_status != completed && $upload_status != duplicate ]]; then
            printf '[%s] ERROR: upload failed for %s (status=%s)\n' \
                "$host_label" "$name" "${upload_status:-invalid-response}" >&2
            failed=$((failed + 1))
            continue
        fi

        insert_list=$(jq -cn \
            --argjson current "$insert_list" \
            --argjson created "$(date +%s)" \
            --argjson location_type "$source_location_type" \
            --arg server "$source_server" \
            --argjson format "$format" \
            --arg name "$name" \
            --arg user "${NG1_USER^^}" \
            --argjson bytes "$size" \
            '$current + [{Created_Timestamp_UTC_Sec:$created,Is_Private:1,
              Source_Location_Id:0,Source_Location_Type:$location_type,
              Source_Server_IP:$server,Trace_File_Directory:"/",
              Trace_File_Format:$format,Trace_File_Type:1,Trace_File_Name:$name,
              Launch_Module:"Data Mining",User_Created:$user,Total_Bytes:$bytes}]') || return 1
        added=$((added + 1))
    done

    if [[ $(jq 'length' <<< "$insert_list") -gt 0 ]]; then
        local insert_data
        insert_data=$(jq -cn --argjson files "$insert_list" '{InsertTraceFileList:$files}') || return 1
        pa_request 101 "$insert_data" "$response_json" || return 1
        if [[ $(jq -r '.Status // empty' "$response_json") != success ]]; then
            printf '[%s] ERROR: File Analysis registration failed: %s\n' \
                "$host_label" "$(jq -c . "$response_json")" >&2
            return 1
        fi
    fi

    pa_request 100 '{}' "$response_json" || return 1
    for file in "${PCAP_FILES[@]}"; do
        name=${file##*/}
        size=$(stat -c %s "$file") || return 1
        if ! jq -e --arg name "$name" --argjson bytes "$size" \
            'any(.Data.TraceFiles[]?;
                 .Trace_File_Name == $name and (.Total_Bytes | tonumber) == $bytes)' \
            "$response_json" >/dev/null; then
            printf '[%s] VERIFY FAILED: %s (%s bytes)\n' \
                "$host_label" "$name" "$size" >&2
            failed=$((failed + 1))
        fi
    done

    printf '[%s] DONE: uploaded/registered=%s already-present=%s failures=%s\n' \
        "$host_label" "$added" "$skipped" "$failed"
    [[ $failed -eq 0 ]]
}

host_count=0
host_failures=0
while IFS= read -r raw_line || [[ -n $raw_line ]]; do
    host=$(trim_line "$raw_line")
    [[ -n $host ]] || continue
    host_count=$((host_count + 1))
    if upload_host "$host"; then
        :
    else
        printf '[%s] HOST FAILED\n' "$host" >&2
        host_failures=$((host_failures + 1))
    fi
done < "$HOSTS_FILE"

cleanup_current_host
unset NG1_PASSWORD

[[ $host_count -gt 0 ]] || {
    printf 'ERROR: no hosts found in %s\n' "$HOSTS_FILE" >&2
    exit 2
}

if [[ $host_failures -gt 0 ]]; then
    printf '\nCompleted with %s failed host(s) out of %s.\n' "$host_failures" "$host_count" >&2
    exit 1
fi

printf '\nAll %s host(s) completed successfully.\n' "$host_count"
