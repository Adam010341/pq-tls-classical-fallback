#!/bin/bash
# probe_smtp.sh <host> <ip> <port> <label> <groups> <tracefile> <ehlo-name> <timeout-seconds>
# One SMTP STARTTLS + TLS 1.3 handshake with OpenSSL s_client -starttls smtp, pinned to <ip>, SNI = <host> (the MX host
# name being probed), EHLO name = <ehlo-name>. Prints one token like probe_one.sh (the awk below is byte-identical).
# What s_client 3.5 sends in this mode (measured with a fake SMTP server, tests s01; evidence/smtp-starttls-client-bytes.txt):
# nothing until the server's greeting; then "EHLO <ehlo-name>\r\n"; then "STARTTLS\r\n"; then the TLS handshake. stdin
# is /dev/null, so after the handshake s_client sends close_notify and closes the TCP connection: no MAIL, RCPT, DATA or
# QUIT, zero bytes of application data. s_client does not check SMTP reply codes: it sends EHLO after a 5xx greeting,
# STARTTLS when the EHLO reply does not offer it, and its ClientHello even after a refused STARTTLS (see README).
# <timeout-seconds> bounds the whole exchange, greeting included (run.py --smtp-timeout).
O=${OPENSSL:-openssl}
h=$1; ip=$2; port=$3; lab=$4; groups=$5; tf=$6; ehlo=$7; T=$8
case "$ip" in *:*) addr="[$ip]:$port" ;; *) addr="$ip:$port" ;; esac
timeout "$T" "$O" s_client -connect "$addr" -starttls smtp -name "$ehlo" -servername "$h" -tls1_3 -groups "$groups" -trace < /dev/null > "$tf" 2>&1
awk '/^(Sent|Received) /{d=$1} /ClientHello, Length/{ch++} /HelloRetryRequest/{hrr=1} /ServerHello, Length/{sh++} /extension_type=key_share/{ks=1} /extension_type=/{if($0!~/key_share/)ks=0} ks&&/NamedGroup:/{g=$2} sh&&ks&&/NamedGroup:/{last=$2} /alert|Alert/{al=1} END{printf "%s|ch=%d|hrr=%d|sh=%d|grp=%s", (sh>0?"ok":"fail"), ch, (ch>=2?1:0), sh, (sh>0?last:"-")}' "$tf"
