#!/usr/bin/env bash
set -euo pipefail
TESTDIR="${1:-/var/tmp/iouring-study/targets}"
mkdir -p "$TESTDIR"
cat > "$TESTDIR/shadow.decoy" <<'DEC'
root:$6$FAKESALT$FAKEHASHdoesNotWorkForAnything:19000:0:99999:7:::
decoyuser:$6$FAKESALT$ALSOFAKE:19000:0:99999:7:::
DEC
cat > "$TESTDIR/id_rsa.decoy" <<'DEC'
-----BEGIN OPENSSH PRIVATE KEY-----
THIS-IS-NOT-A-REAL-KEY-ONLY-FOR-MONITOR-PATH-TESTING
AAAA0000FAKEFAKEFAKE1111deadbeefNOTVALID2222
-----END OPENSSH PRIVATE KEY-----
DEC
cat > "$TESTDIR/audit.decoy.log" <<'DEC'
type=DECOY msg=audit(0000000000.000:1): seed line, safe to overwrite
DEC
for f in shadow.decoy id_rsa.decoy audit.decoy.log; do truncate -s 8192 "$TESTDIR/$f"; done
chmod 600 "$TESTDIR/shadow.decoy" "$TESTDIR/id_rsa.decoy"
chmod 644 "$TESTDIR/audit.decoy.log"
echo "Decoys created in: $TESTDIR"; ls -l "$TESTDIR"
FSTYPE=$(findmnt -n -o FSTYPE --target "$TESTDIR" 2>/dev/null || echo "?")
echo "filesystem backing $TESTDIR: $FSTYPE"
[ "$FSTYPE" = "tmpfs" ] && echo "WARNING: $TESTDIR is tmpfs (RAM) — block monitor will see nothing."
