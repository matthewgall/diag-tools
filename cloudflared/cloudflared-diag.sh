#!/usr/bin/env bash
#
# cloudflared-diag.sh
#
# Reproduces the connectivity pre-checks that cloudflared runs at startup:
#   1. SRV discovery for region*.v2.argotunnel.com
#   2. UDP/QUIC handshake to the resolved edge IPs (port 7844 by default)
#   3. TCP/TLS handshake to the resolved edge IPs (port 7844 by default)
#
# This script intentionally does NOT depend on the cloudflared binary or its
# libraries, so a failure here means the network path is blocked, not a bug in
# cloudflared.
#
# Usage:
#   ./cloudflared-diag.sh [region] [dns-server]
#
# The optional [dns-server] argument lets you override the resolver. If omitted,
# the system resolver is used.
#
# Examples:
#   ./cloudflared-diag.sh
#   ./cloudflared-diag.sh us
#   ./cloudflared-diag.sh us 1.1.1.1
#   ./cloudflared-diag.sh "" 8.8.8.8
#

set -u

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SRV_SERVICE="v2-origintunneld"
SRV_PROTO="tcp"
SRV_DOMAIN="argotunnel.com"

PROBE_SNI="probe.cftunnel.com"
QUIC_ALPN="argotunnel"
DEFAULT_EDGE_PORT="7844"

# Probe timeout in seconds
PROBE_TIMEOUT=8

# Cloudflare Origin CA root certificates (from cloudflared/tlsconfig/cloudflare_ca.go).
# The edge presents a certificate signed by one of these during the probe handshake.
CF_ORIGIN_CA_PEM=$(cat <<'EOF'
-----BEGIN CERTIFICATE-----
MIICiTCCAi6gAwIBAgIUXZP3MWb8MKwBE1Qbawsp1sfA/Y4wCgYIKoZIzj0EAwIw
gY8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1T
YW4gRnJhbmNpc2NvMRkwFwYDVQQKExBDbG91ZEZsYXJlLCBJbmMuMTgwNgYDVQQL
Ey9DbG91ZEZsYXJlIE9yaWdpbiBTU0wgRUNDIENlcnRpZmljYXRlIEF1dGhvcml0
eTAeFw0xOTA4MjMyMTA4MDBaFw0yOTA4MTUxNzAwMDBaMIGPMQswCQYDVQQGEwJV
UzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEZ
MBcGA1UEChMQQ2xvdWRGbGFyZSwgSW5jLjE4MDYGA1UECxMvQ2xvdWRGbGFyZSBP
cmlnaW4gU1NMIEVDQyBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAASR+sGALuaGshnUbcxKry+0LEXZ4NY6JUAtSeA6g87K3jaA
xpIg9G50PokpfWkhbarLfpcZu0UAoYy2su0EhN7wo2YwZDAOBgNVHQ8BAf8EBAMC
AQYwEgYDVR0TAQH/BAgwBgEB/wIBAjAdBgNVHQ4EFgQUhTBdOypw1O3VkmcH/es5
tBoOOKcwHwYDVR0jBBgwFoAUhTBdOypw1O3VkmcH/es5tBoOOKcwCgYIKoZIzj0E
AwIDSQAwRgIhAKilfntP2ILGZjwajktkBtXE1pB4Y/fjAfLkIRUzrI15AiEA5UCL
XYZZ9m2c3fKwIenMMojL1eqydsgqj/wK4p5kagQ=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEADCCAuigAwIBAgIID+rOSdTGfGcwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV
BAYTAlVTMRkwFwYDVQQKExBDbG91ZEZsYXJlLCBJbmMuMTQwMgYDVQQLEytDbG91
ZEZsYXJlIE9yaWdpbiBTU0wgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MRYwFAYDVQQH
Ew1TYW4gRnJhbmNpc2NvMRMwEQYDVQQIEwpDYWxpZm9ybmlhMB4XDTE5MDgyMzIx
MDgwMFoXDTI5MDgxNTE3MDAwMFowgYsxCzAJBgNVBAYTAlVTMRkwFwYDVQQKExBD
bG91ZEZsYXJlLCBJbmMuMTQwMgYDVQQLEytDbG91ZEZsYXJlIE9yaWdpbiBTU0wg
Q2VydGlmaWNhdGUgQXV0aG9yaXR5MRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRMw
EQYDVQQIEwpDYWxpZm9ybmlhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAwEiVZ/UoQpHmFsHvk5isBxRehukP8DG9JhFev3WZtG76WoTthvLJFRKFCHXm
V6Z5/66Z4S09mgsUuFwvJzMnE6Ej6yIsYNCb9r9QORa8BdhrkNn6kdTly3mdnykb
OomnwbUfLlExVgNdlP0XoRoeMwbQ4598foiHblO2B/LKuNfJzAMfS7oZe34b+vLB
yrP/1bgCSLdc1AxQc1AC0EsQQhgcyTJNgnG4va1c7ogPlwKyhbDyZ4e59N5lbYPJ
SmXI/cAe3jXj1FBLJZkwnoDKe0v13xeF+nF32smSH0qB7aJX2tBMW4TWtFPmzs5I
lwrFSySWAdwYdgxw180yKU0dvwIDAQABo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYD
VR0TAQH/BAgwBgEB/wIBAjAdBgNVHQ4EFgQUJOhTV118NECHqeuU27rhFnj8KaQw
HwYDVR0jBBgwFoAUJOhTV118NECHqeuU27rhFnj8KaQwDQYJKoZIhvcNAQELBQAD
ggEBAHwOf9Ur1l0Ar5vFE6PNrZWrDfQIMyEfdgSKofCdTckbqXNTiXdgbHs+TWoQ
wAB0pfJDAHJDXOTCWRyTeXOseeOi5Btj5CnEuw3P0oXqdqevM1/+uWp0CM35zgZ8
VD4aITxity0djzE6Qnx3Syzz+ZkoBgTnNum7d9A66/V636x4vTeqbZFBr9erJzgz
hhurjcoacvRNhnjtDRM0dPeiCJ50CP3wEYuvUzDHUaowOsnLCjQIkWbR7Ni6KEIk
MOz2U0OBSif3FTkhCgZWQKOOLo1P42jHC3ssUZAtVNXrCk3fw9/E15k8NPkBazZ6
0iykLhH1trywrKRMVw67F44IE8Y=
-----END CERTIFICATE-----
EOF
)

# Parse arguments. Region and DNS server are both optional.
REGION=""
DNS_SERVER=""

if [[ $# -ge 1 ]]; then
  REGION="$1"
fi
if [[ $# -ge 2 ]]; then
  DNS_SERVER="$2"
fi

if [[ -n "$REGION" ]]; then
  SRV_QNAME="_${REGION}-${SRV_SERVICE}._${SRV_PROTO}.${SRV_DOMAIN}"
  REGION_LABEL="${REGION}"
else
  SRV_QNAME="_${SRV_SERVICE}._${SRV_PROTO}.${SRV_DOMAIN}"
  REGION_LABEL="global"
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

pass() { printf "\033[32mPASS\033[0m\n"; }
fail() { printf "\033[31mFAIL\033[0m: %s\n" "$1"; }
skip() { printf "\033[33mSKIP\033[0m: %s\n" "$1"; }
info() { printf "\033[36mINFO\033[0m: %s\n" "$1"; }

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Print a horizontal rule
hr() { printf '%*s\n' "${1:-80}" '' | tr ' ' '-'; }

# Build DNS tool arguments depending on whether a DNS server override was set.
# resolve_srv <qname> [dns_server]
resolve_srv() {
  local qname="$1"
  local dns_server="${2:-}"
  local records=""

  if command_exists dig; then
    if [[ -n "$dns_server" ]]; then
      records=$(dig "@${dns_server}" +short srv "$qname" 2>/dev/null || true)
    else
      records=$(dig +short srv "$qname" 2>/dev/null || true)
    fi
    echo "$records"
    return
  fi

  if command_exists host; then
    if [[ -n "$dns_server" ]]; then
      records=$(host -t srv "$qname" "$dns_server" 2>/dev/null | awk '/has SRV record/ {print $8,$9,$10,$11}' || true)
    else
      records=$(host -t srv "$qname" 2>/dev/null | awk '/has SRV record/ {print $8,$9,$10,$11}' || true)
    fi
    echo "$records"
    return
  fi

  if command_exists nslookup; then
    if [[ -n "$dns_server" ]]; then
      records=$(nslookup -type=srv "$qname" "$dns_server" 2>/dev/null |
                awk '/service =/ {gsub(/=/,""); print $6,$7,$8,$9}' || true)
    else
      records=$(nslookup -type=srv "$qname" 2>/dev/null |
                awk '/service =/ {gsub(/=/,""); print $6,$7,$8,$9}' || true)
    fi
    echo "$records"
    return
  fi

  return 1
}

# resolve_ips <hostname> [dns_server]
resolve_ips() {
  local host="$1"
  local dns_server="${2:-}"
  local ips=""

  if command_exists dig; then
    if [[ -n "$dns_server" ]]; then
      ips=$(dig "@${dns_server}" +short "$host" A 2>/dev/null; dig "@${dns_server}" +short "$host" AAAA 2>/dev/null)
    else
      ips=$(dig +short "$host" A 2>/dev/null; dig +short "$host" AAAA 2>/dev/null)
    fi
  elif command_exists host; then
    if [[ -n "$dns_server" ]]; then
      ips=$(host -t A "$host" "$dns_server" 2>/dev/null | awk '/has address/ {print $4}';
            host -t AAAA "$host" "$dns_server" 2>/dev/null | awk '/has IPv6 address/ {print $5}')
    else
      ips=$(host -t A "$host" 2>/dev/null | awk '/has address/ {print $4}';
            host -t AAAA "$host" 2>/dev/null | awk '/has IPv6 address/ {print $5}')
    fi
  elif command_exists nslookup; then
    if [[ -n "$dns_server" ]]; then
      ips=$(nslookup "$host" "$dns_server" 2>/dev/null | awk '/^Address: / {print $2}' | sed '/#.*#/!d')
    else
      ips=$(nslookup "$host" 2>/dev/null | awk '/^Address: / {print $2}' | sed '/#.*#/!d')
    fi
  else
    return 1
  fi

  # Filter out empty lines
  echo "$ips" | grep -v '^$'
}

# Check basic TCP reachability to an IP:port.
check_tcp_port() {
  local ip="$1"
  local port="$2"

  if (exec 3<>"/dev/tcp/${ip}/${port}") 2>/dev/null; then
    exec 3<&- 3>&-
    return 0
  fi

  if command_exists nc; then
    if timeout "$PROBE_TIMEOUT" nc -vz -w "$PROBE_TIMEOUT" "$ip" "$port" >/dev/null 2>&1; then
      return 0
    fi
  fi

  return 1
}

# Check TLS handshake for the HTTP/2 probe (SNI probe.cftunnel.com).
check_http2_tls() {
  local ip="$1"
  local port="$2"

  if ! command_exists openssl; then
    return 2
  fi

  local out
  out=$(echo | timeout "$PROBE_TIMEOUT" openssl s_client \
    -connect "${ip}:${port}" \
    -servername "$PROBE_SNI" \
    -tls1_3 \
    -CAfile "$CA_FILE" 2>/dev/null) || true

  if echo "$out" | grep -q 'Verify return code: 0 '; then
    return 0
  fi
  return 1
}

# Check QUIC handshake (requires OpenSSL 3.2+ with -quic support).
check_quic() {
  local ip="$1"
  local port="$2"

  if ! command_exists openssl; then
    return 2
  fi

  if ! openssl s_client -quic -help >/dev/null 2>&1; then
    return 2
  fi

  local out
  out=$(echo | timeout "$PROBE_TIMEOUT" openssl s_client -quic \
    -connect "${ip}:${port}" \
    -servername "$PROBE_SNI" \
    -alpn "$QUIC_ALPN" \
    -CAfile "$CA_FILE" 2>/dev/null) || true

  if echo "$out" | grep -q 'Verify return code: 0 '; then
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Build a temporary CA bundle so openssl/curl can verify the Cloudflare Origin
# Certificate returned by the edge. This matches what cloudflared does internally.
if command_exists mktemp; then
  CA_FILE=$(mktemp /tmp/cf_origin_ca.XXXXXX.pem)
else
  CA_FILE="/tmp/cf_origin_ca.pem"
fi
trap 'rm -f "$CA_FILE"' EXIT
printf '%s\n' "$CF_ORIGIN_CA_PEM" > "$CA_FILE"

clear 2>/dev/null || true
hr 80
printf "Cloudflared edge connectivity reproduction script\n"
printf "Region:      %s\n" "$REGION_LABEL"
printf "SRV query:   %s\n" "$SRV_QNAME"
if [[ -n "$DNS_SERVER" ]]; then
  printf "DNS server:  %s (override)\n" "$DNS_SERVER"
else
  printf "DNS server:  system resolver\n"
fi
hr 80
printf "\n"

# --- 1. DNS discovery ------------------------------------------------------

info "Looking up SRV records for edge discovery..."
if ! command_exists dig && ! command_exists host && ! command_exists nslookup; then
  fail "None of dig/host/nslookup found. Cannot continue DNS checks."
  exit 1
fi

srv_records=$(resolve_srv "$SRV_QNAME" "$DNS_SERVER" || true)
if [[ -z "$srv_records" ]]; then
  fail "No SRV records returned for $SRV_QNAME"
  printf "\nAction: ensure your DNS resolver can resolve '%s'.\n" "$SRV_QNAME"
  if [[ -n "$DNS_SERVER" ]]; then
    printf "Try without [dns-server] to see if the system resolver works,\n"
    printf "or verify that %s answers SRV queries.\n" "$DNS_SERVER"
  else
    printf "Try: dig srv %s @1.1.1.1\n" "$SRV_QNAME"
  fi
  exit 1
fi

printf "\n\033[1mSRV records returned:\033[0m\n"
echo "$srv_records"
printf "\n"

# --- 2. Resolve region hostnames to IPs -------------------------------------

# Each SRV line: priority weight port target
declare -a REGION_HOSTS
REGION_HOSTS=()
while IFS=' ' read -r priority weight port target; do
  # dig may return tabs; normalise whitespace
  target=$(echo "$target" | tr -d '[:space:]')
  if [[ -n "$target" ]]; then
    REGION_HOSTS+=("$target")
  fi
done <<< "$srv_records"

if [[ ${#REGION_HOSTS[@]} -eq 0 ]]; then
  fail "Could not parse SRV targets from DNS response"
  exit 1
fi

info "Resolving SRV targets to IP addresses..."
declare -A HOST_IPS
for host in "${REGION_HOSTS[@]}"; do
  ips=$(resolve_ips "$host" "$DNS_SERVER" || true)
  if [[ -z "$ips" ]]; then
    fail "Could not resolve $host to an IP address"
  else
    HOST_IPS["$host"]="$ips"
    printf "%-40s -> %s\n" "$host" "$(echo "$ips" | tr '\n' ' ')"
  fi
done

# --- 3. Transport probes ----------------------------------------------------

printf "\n"
hr 80
printf "\033[1mTransport probes\033[0m\n"
hr 80
printf "\n"

for host in "${REGION_HOSTS[@]}"; do
  ips=${HOST_IPS[$host]:-}
  if [[ -z "$ips" ]]; then
    continue
  fi

  # Determine the port from the SRV record; fall back to 7844
  port=$(echo "$srv_records" | awk -v t="$host" '{gsub(/[:space:]*$/, "", $4); if ($4 == t) print $3;}' | head -n1)
  port=${port:-$DEFAULT_EDGE_PORT}

  printf "\033[1mTarget: %s (port %s)\033[0m\n" "$host" "$port"
  hr 60

  while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue

    printf "  IP: %-39s TCP open  -> " "$ip"
    if check_tcp_port "$ip" "$port"; then
      pass
    else
      fail "port ${port}/tcp unreachable"
    fi

    printf "  IP: %-39s H2 TLS   -> " "$ip"
    if check_http2_tls "$ip" "$port"; then
      pass
    elif [[ $? -eq 2 ]]; then
      skip "openssl not available or too old"
    else
      fail "TLS handshake with SNI ${PROBE_SNI} failed"
    fi

    printf "  IP: %-39s QUIC    -> " "$ip"
    check_quic "$ip" "$port"
    ret=$?
    if [[ $ret -eq 0 ]]; then
      pass
    elif [[ $ret -eq 2 ]]; then
      skip "openssl 3.2+ with -quic required"
    else
      fail "QUIC handshake with SNI ${PROBE_SNI} ALPN ${QUIC_ALPN} failed"
    fi

    printf "\n"
  done <<< "$ips"
done

# --- 4. Optional curl-based HTTP/2 probe ------------------------------------

printf "\n"
hr 80
printf "\033[1mOptional curl HTTP/2 probe\033[0m (sends a real HTTP request)\n"
hr 80
printf "\n"

if ! command_exists curl; then
  skip "curl not installed"
else
  for host in "${REGION_HOSTS[@]}"; do
    ips=${HOST_IPS[$host]:-}
    [[ -z "$ips" ]] && continue

    # Use the first IP for curl
    first_ip=$(echo "$ips" | head -n1)
    port=$(echo "$srv_records" | awk -v t="$host" '{gsub(/[:space:]*$/, "", $4); if ($4 == t) print $3;}' | head -n1)
    port=${port:-$DEFAULT_EDGE_PORT}

    info "curl -v --http2 --resolve ${PROBE_SNI}:${port}:${first_ip} --cacert ${CA_FILE} https://${PROBE_SNI}:${port}/"
    curl -v --http2 --resolve "${PROBE_SNI}:${port}:${first_ip}" \
      --cacert "$CA_FILE" \
      --max-time "$PROBE_TIMEOUT" \
      "https://${PROBE_SNI}:${port}/" 2>&1 | tail -n 5 || true
    printf "\n"
  done
fi

# --- 5. Summary -------------------------------------------------------------

hr 80
printf "\033[1mSummary\033[0m\n"
info "If all TCP/H2/QUIC probes FAIL, outbound port 7844 is likely blocked."
info "If TCP/H2 passes but QUIC fails, UDP/QUIC to port 7844 is blocked."
info "If DNS fails first, fix DNS resolution before debugging transport."
info "Cloudflared production SNI is probe.cftunnel.com for these probes."
hr 80
