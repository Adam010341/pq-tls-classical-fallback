#!/bin/bash
# probe_quic.sh <host> <ip> <port> <label> <groups> <tracefile> <timeout-seconds>
# One QUIC (ALPN h3) TLS 1.3 handshake with OpenSSL s_client -quic, pinned to <ip> (UDP), SNI = <host>. Prints one
# token like probe_one.sh (the last line, the awk summariser, is byte-identical, so the tokens stay comparable).
# What s_client 3.5.6 sends (measured on loopback with tests/qsrv.c and a datagram counter; tests q01-q02;
# evidence/quic-client-behaviour.txt): the ClientHello, a second one after a Retry or a HelloRetryRequest, ACKs, its
# Finished, a few PINGs and one CONNECTION_CLOSE, 7 to 13 datagrams in all; usually only Initial and Handshake packets,
# sometimes also a small 1-RTT packet or two (an ACK, an application close); never a STREAM frame, so no stream and no
# HTTP/3 request (stdin is /dev/null). A host that does not answer gets 5 datagrams in 8 s (at 0, 0, 1, 3 and 7 s; a P1
# ClientHello fills two), also when the port is closed (s_client ignores ICMP port unreachable).
# Two stops besides <timeout-seconds> (run.py --quic-timeout): s_client is killed as soon as its trace shows its
# MAX_DATAGRAMS-th sent datagram, or when the trace reaches TRACE_CAP bytes. Reason: after a failed handshake s_client
# and an OpenSSL server can answer each other's PINGs without end (lab-B11; test q02: about 15,000 datagrams per second
# each way on loopback). s_client ignores SIGPIPE, so cutting its output alone does not stop it; it must be killed.
# stdbuf -oL makes s_client write every trace line at once, so the count is current (and a probe killed at the timeout
# keeps its whole trace). stdout (the -trace) and stderr are kept apart while s_client runs (in QUIC mode certificate-
# verify lines on stderr interleave with -trace lines and cut message headers, lab-B11); stderr (at most 64 KiB) is
# appended after a marker line.
O=${OPENSSL:-openssl}
TRACE_CAP=1048576
MAX_DATAGRAMS=40
h=$1; ip=$2; port=$3; lab=$4; groups=$5; tf=$6; T=$7
case "$ip" in *:*) addr="[$ip]:$port" ;; *) addr="$ip:$port" ;; esac
( ( echo "$BASHPID" > "$tf.pid"; exec timeout -k 2 "$T" stdbuf -oL "$O" s_client -quic -alpn h3 -connect "$addr" -servername "$h" \
      -groups "$groups" -trace < /dev/null ) 2>&1 1>&3 3>&- | head -c 65536 > "$tf.err" ) 3>&1 \
  | LC_ALL=C awk -v cap="$TRACE_CAP" -v maxdg="$MAX_DATAGRAMS" -v pf="$tf.pid" -v out="$tf" '
      function stop(why,  pid) { getline pid < pf; system("kill -TERM " pid " 2>/dev/null")
                                 printf "---- probe_quic.sh: s_client stopped: %s ----\n", why > out; exit }
      { n += length($0) + 1; if (n > cap) stop("trace reached " cap " bytes"); print > out
        if ($0 ~ /^Sent Datagram/ && ++dg >= maxdg) stop(dg " datagrams sent") }'
{ printf -- '---- stderr ----\n'; cat "$tf.err"; } >> "$tf" 2>/dev/null; rm -f "$tf.err" "$tf.pid"
awk '/^(Sent|Received) /{d=$1} /ClientHello, Length/{ch++} /HelloRetryRequest/{hrr=1} /ServerHello, Length/{sh++} /extension_type=key_share/{ks=1} /extension_type=/{if($0!~/key_share/)ks=0} ks&&/NamedGroup:/{g=$2} sh&&ks&&/NamedGroup:/{last=$2} /alert|Alert/{al=1} END{printf "%s|ch=%d|hrr=%d|sh=%d|grp=%s", (sh>0?"ok":"fail"), ch, (ch>=2?1:0), sh, (sh>0?last:"-")}' "$tf"
