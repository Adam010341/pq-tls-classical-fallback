#!/bin/bash
# kit-c offline test runner. Sends nothing to any other host: the tests run inside `unshare -Urnm` (loopback only),
# with DNS answered by a local stub and all test files on a tmpfs (the QUIC test server tests/qsrv.c is compiled there
# with gcc). Usage: bash run_tests.sh [test-name-prefix ...]
# KITC_QUIC_EVIDENCE=FILE bash run_tests.sh q01 q02   rewrites evidence/quic-client-behaviour.txt from tests q01-q02.
set -u
cd "$(dirname "$0")"
export OPENSSL=${OPENSSL:-openssl}
st=0
echo "== static checks"
if python3 -I -c 'import ast, sys; [ast.parse(open(f).read(), f) for f in sys.argv[1:]]' run.py guard.py dnsclient.py mxlist.py \
      quic_targets.py tests/test_kit.py tests/stub_dns.py tests/fake_dns.py tests/fake_smtp.py \
   && bash -n probe_one.sh && bash -n probe_smtp.sh && bash -n probe_quic.sh && bash -n run_tests.sh && bash -n launch/launch-cron.sh \
   && [ "$(grep -c "^awk '" probe_one.sh)" = 1 ] && [ "$(grep "^awk '" probe_one.sh)" = "$(grep "^awk '" probe_smtp.sh)" ] \
   && [ "$(grep "^awk '" probe_one.sh)" = "$(grep "^awk '" probe_quic.sh)" ] \
   && [ "$(tail -n 1 probe_one.sh)" = "$(tail -n 1 probe_quic.sh)" ]; then
  echo "syntax: ok (probe_smtp.sh and probe_quic.sh awk identical to probe_one.sh; the summariser is probe_quic.sh's last line)"
else echo "syntax: FAILED"; st=1; fi
if sha256sum -c --quiet SHA256SUMS; then echo "SHA256SUMS: ok ($(wc -l < SHA256SUMS) files)"; else echo "SHA256SUMS: MISMATCH"; st=1; fi
echo "OpenSSL: $($OPENSSL version)"
echo "== tests (unshare -Urnm, loopback only, tmpfs work dir)"
python3 -I tests/test_kit.py "$@" 2>&1 | tee test-run.log
t=${PIPESTATUS[0]}
echo
echo "== SUMMARY: static checks $([ $st = 0 ] && echo passed || echo FAILED); $(grep '^RESULT:' test-run.log | tail -1)"
[ $st = 0 ] && [ $t = 0 ]
