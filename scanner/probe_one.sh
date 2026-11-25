#!/bin/bash
# probe_one.sh <host> <ip> <port> <label> <groups> <tracefile>
# One TLS 1.3 handshake with OpenSSL s_client, pinned to <ip> (IPv4 or IPv6), SNI = <host>. Prints one token:
#   ok|ch=N|hrr=0/1|sh=N|grp=NAME   (or fail|...)   -- same summariser (awk) as the pilot and campaign 2.
# kit-c change: stdin is /dev/null instead of `echo |`. s_client reads stdin only after the handshake has completed;
# it then sees end-of-file, prints DONE and closes with close_notify. So a completed probe sends ZERO bytes of
# application data (the old `echo |` sent one newline byte). Checked by tests/test_kit.py (p01, p02) with s_server -trace.
O=${OPENSSL:-openssl}
T=${PROBE_TIMEOUT:-12}
h=$1; ip=$2; port=$3; lab=$4; groups=$5; tf=$6
case "$ip" in *:*) addr="[$ip]:$port" ;; *) addr="$ip:$port" ;; esac
timeout "$T" "$O" s_client -connect "$addr" -servername "$h" -tls1_3 -groups "$groups" -trace < /dev/null > "$tf" 2>&1
awk '/^(Sent|Received) /{d=$1} /ClientHello, Length/{ch++} /HelloRetryRequest/{hrr=1} /ServerHello, Length/{sh++} /extension_type=key_share/{ks=1} /extension_type=/{if($0!~/key_share/)ks=0} ks&&/NamedGroup:/{g=$2} sh&&ks&&/NamedGroup:/{last=$2} /alert|Alert/{al=1} END{printf "%s|ch=%d|hrr=%d|sh=%d|grp=%s", (sh>0?"ok":"fail"), ch, (ch>=2?1:0), sh, (sh>0?last:"-")}' "$tf"
