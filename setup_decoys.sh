# create benign stand-in files for the workload to touch.
set -euo pipefail

TESTDIR="${1:-/tmp/iouring-study/targets}"
mkdir -p "$TESTDIR"

# A credential-store stand-in (shape of /etc/shadow, fake entries).
cat > "$TESTDIR/shadow.decoy" <<'EOF'
root:$6$FAKESALT$FAKEHASHdoesNotWorkForAnything:19000:0:99999:7:::
decoyuser:$6$FAKESALT$ALSOFAKE:19000:0:99999:7:::
EOF

# An SSH-private-key stand-in (right shape, not a real key — can't authenticate).
cat > "$TESTDIR/id_rsa.decoy" <<'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
THIS-IS-NOT-A-REAL-KEY-ONLY-FOR-MONITOR-PATH-TESTING
AAAA0000FAKEFAKEFAKE1111deadbeefNOTVALID2222
-----END OPENSSH PRIVATE KEY-----
EOF

# An audit-log stand-in (the write/append target).
cat > "$TESTDIR/audit.decoy.log" <<'EOF'
type=DECOY msg=audit(0000000000.000:1): seed line, safe to overwrite
EOF

# Make the shadow/key decoys 0600 like the real ones, so permission-path
# behaviour matches. Run the workload as the owner (or root) so opens succeed.
chmod 600 "$TESTDIR/shadow.decoy" "$TESTDIR/id_rsa.decoy"
chmod 644 "$TESTDIR/audit.decoy.log"

echo "Decoys created in: $TESTDIR"
ls -l "$TESTDIR"