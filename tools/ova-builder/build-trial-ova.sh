#!/bin/bash
# build-trial-ova.sh — mint a customer-specific trial OVA from the
# golden image.
#
# Pipeline:
#   0. (Optional) Stage service images into the local k3d cluster so the
#      golden VM build can grab them from the cluster's containerd
#   0.5. (Optional) Prime postgres/redis StatefulSets, wait for Ready, then
#      helm install the rest — mirrors trial firstboot ordering
#   1. Mint a signed JWS license  (license-gen)
#   2. Linked-clone the golden qcow2 (instant, zero-copy)
#   3. virt-customize: copy license + set hostname, regenerate SSH host keys
#   4. qemu-img convert qcow2 → VMDK streamOptimized (compresses ~3x)
#   5. Render OVF from template (variable substitution)
#   6. Build manifest file (sha256 of every artefact)
#   7. tar everything in OVF-spec order: ovf, mf, vmdk
#
# Usage:
#   ./build-trial-ova.sh "ACME Corp <eval@acme.com>"
#   ./build-trial-ova.sh "ACME Corp" 30
#   ./build-trial-ova.sh "ACME Corp" 30 --features sandbox,correlation
#   GOLDEN_DISK=/path/to/custom-golden.qcow2 ./build-trial-ova.sh "ACME" 45
#
# Inputs (env-tunable):
#   GOLDEN_DISK      Path to ti-platform-golden.qcow2 (default: ./packer/build/…)
#   LICENSE_PRIV_KEY Path to Ed25519 private key (default: ~/.ti-platform/license.priv)
#   DIST_DIR         Where to drop the .ova (default: ./dist)
#   FEATURES         Comma-separated feature list (default: "full"); the
#                    --features CLI flag (if given) wins over this env.
#
# Canonical feature set the operator can toggle (everything else is
# always-on):
#     monitoring sandbox icap correlation enrichment
#     vendor_audit minio neo4j attack_paths
# Each feature in --features → `--set <name>.enabled=true`;
# every other canonical feature → `--set <name>.enabled=false`.
# Resolved enable/disable values get baked into the cloned qcow2 at
# /opt/ti-platform/etc/values-features.yaml so the firstboot helm
# install layers them on top of values-trial-ova.yaml.
#   STAGE_IMAGES     1 = export+import service images into the build k3d
#                    cluster before building (default: 0 — skip).  Set to 1
#                    when running inside the ti-api pod that drives the
#                    build out of its own k3d cluster.
#   STAGE_PHASE1     1 = run phase-1 (postgres + redis StatefulSets first,
#                    wait Ready, helm install the rest) before the build
#                    (default: 0).  Mirrors the trial-VM firstboot ordering
#                    so we don't reproduce the helm-races we hit in May.
#   K3D_CLUSTER      k3d cluster name for stage steps (default: ti-k8s)
#
# Output:
#   $DIST_DIR/ti-platform-trial-{slug}-{days}d.ova
#
# ──────────────────────────────────────────────────────────────────────────────
# KVM ACCELERATION NOTE
# ──────────────────────────────────────────────────────────────────────────────
# virt-customize and qemu-img convert can both use /dev/kvm for hardware
# acceleration.  Without /dev/kvm access libguestfs silently falls back to
# TCG (full software emulation) which is roughly 10× slower — a 3-minute
# build becomes a 30-minute build.
#
# We deliberately do NOT try to mount /dev/kvm from inside this script.
# Mounting requires either:
#   - host-level config (`docker run --device /dev/kvm` /
#     `k3d cluster create --volume /dev/kvm:/dev/kvm@server:0`), OR
#   - the API pod running with privileged: true and the cluster nodes
#     exposing /dev/kvm.
#
# Operators who want the fast path should flip
#   api.securityContext.privileged: true
# in deploy/k8s/charts/ti-platform/values-trials-builder.yaml AND ensure
# the host has /dev/kvm exposed to the cluster.  Otherwise the build
# completes correctly — just slowly — under TCG.
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Canonical modular features ────────────────────────────────────────────────
# Keep in sync with services/api/app/routers/trials.py:CANONICAL_FEATURES.
CANONICAL_FEATURES=(
    monitoring
    sandbox
    icap
    correlation
    enrichment
    vendor_audit
    minio
    neo4j
    attack_paths
)

# ── Inputs ────────────────────────────────────────────────────────────────────
CUSTOMER=""
DAYS=""
FEATURES_FLAG=""

# Two positional args (customer, days) plus an optional --features flag.
# Parse the flag out first so it can appear anywhere; the remaining args
# fill the positionals in order.
_positional=()
while [ $# -gt 0 ]; do
    case "$1" in
        --features)
            FEATURES_FLAG="${2:-}"
            shift 2
            ;;
        --features=*)
            FEATURES_FLAG="${1#--features=}"
            shift
            ;;
        -h|--help)
            cat <<EOF >&2
usage: $0 <customer> [days] [--features f1,f2,...]

  customer    Customer label, e.g. "ACME Corp <eval@acme.com>"
  days        Trial duration: 15, 30, or 45  (default 30)
  --features  Comma-separated subset of:
              ${CANONICAL_FEATURES[*]}
              (defaults to FEATURES env or "full")

example:
  $0 "ACME Corp <eval@acme.com>" 30 --features sandbox,correlation
EOF
            exit 0
            ;;
        *)
            _positional+=("$1")
            shift
            ;;
    esac
done
CUSTOMER="${_positional[0]:-}"
DAYS="${_positional[1]:-30}"

if [ -z "$CUSTOMER" ]; then
    cat <<EOF >&2
usage: $0 <customer> [days] [--features f1,f2,...]

  customer    Customer label, e.g. "ACME Corp <eval@acme.com>"
  days        Trial duration: 15, 30, or 45  (default 30)
  --features  Subset of: ${CANONICAL_FEATURES[*]}

example:
  $0 "ACME Corp <eval@acme.com>" 30 --features sandbox,correlation
EOF
    exit 2
fi

case "$DAYS" in
    15|30|45) ;;
    *) echo "days must be 15 / 30 / 45  (got: $DAYS)" >&2; exit 2 ;;
esac

# ── Paths ─────────────────────────────────────────────────────────────────────
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
GOLDEN_DISK="${GOLDEN_DISK:-$HERE/packer/build/ti-platform-golden.qcow2}"

# License generator path: check env override → alongside this script → repo
# layout (tools/license-gen/).  When the script runs inside the ti-api pod
# from a ConfigMap mount at /opt/ova-builder/, license_gen.py is co-located,
# so $HERE/license_gen.py wins.  $ROOT-based fallback handles local repo runs.
if [ -n "${LICENSE_GEN:-}" ]; then
    :  # caller-supplied
elif [ -f "$HERE/license_gen.py" ]; then
    LICENSE_GEN="$HERE/license_gen.py"
elif [ -f "$ROOT/tools/license-gen/license_gen.py" ]; then
    LICENSE_GEN="$ROOT/tools/license-gen/license_gen.py"
else
    LICENSE_GEN="$ROOT/tools/license-gen/license_gen.py"  # for the error msg
fi
LICENSE_PRIV_KEY="${LICENSE_PRIV_KEY:-$HOME/.ti-platform/license.priv}"
OVF_TEMPLATE="$HERE/ovf-template.ovf"
DIST_DIR="${DIST_DIR:-$HERE/dist}"
# License "features" field — semantic, used by the licensing JWT only.
# The modular-OVA feature set is separate; see FEATURES_RESOLVED below.
FEATURES="${FEATURES:-full}"

# --features flag wins over $FEATURES env for the helm-flag translation.
# (License JWT still uses $FEATURES — runtime gating is a separate effort.)
if [ -n "$FEATURES_FLAG" ]; then
    OVA_FEATURES="$FEATURES_FLAG"
else
    # When the env was set explicitly to a non-"full" comma list we treat
    # it as the modular set too; "full" means "leave defaults alone".
    if [ "$FEATURES" = "full" ]; then
        OVA_FEATURES=""
    else
        OVA_FEATURES="$FEATURES"
    fi
fi

# Validate every requested feature is in the canonical set, build the
# resolved enable list ($ENABLED_FEATURES) and disable list
# ($DISABLED_FEATURES), and assemble the `--set <k>.enabled=…` flag
# string (HELM_FEATURE_FLAGS) that ti-firstboot.sh will splice into
# `helm upgrade --install`.  Order is stable for log-grep tests.
ENABLED_FEATURES=()
DISABLED_FEATURES=()
HELM_FEATURE_FLAGS=()
if [ -n "$OVA_FEATURES" ]; then
    IFS=',' read -r -a _req <<< "$OVA_FEATURES"
    for f in "${_req[@]}"; do
        f="${f// /}"
        [ -z "$f" ] && continue
        _ok=0
        for c in "${CANONICAL_FEATURES[@]}"; do
            [ "$f" = "$c" ] && { _ok=1; break; }
        done
        if [ "$_ok" -ne 1 ]; then
            printf 'feature %q not in canonical set: %s\n' \
                "$f" "${CANONICAL_FEATURES[*]}" >&2
            exit 2
        fi
    done
    for c in "${CANONICAL_FEATURES[@]}"; do
        _on=0
        for f in "${_req[@]}"; do
            [ "${f// /}" = "$c" ] && { _on=1; break; }
        done
        if [ "$_on" -eq 1 ]; then
            ENABLED_FEATURES+=("$c")
            HELM_FEATURE_FLAGS+=("--set" "${c}.enabled=true")
        else
            DISABLED_FEATURES+=("$c")
            HELM_FEATURE_FLAGS+=("--set" "${c}.enabled=false")
        fi
    done
fi

# Opt-in stage steps.  Default off so local repo builds (which already have
# a populated k3d cluster) don't pay the cost; the API-pod-driven build
# flips both to "1" via env.
STAGE_IMAGES="${STAGE_IMAGES:-0}"
STAGE_PHASE1="${STAGE_PHASE1:-0}"
K3D_CLUSTER="${K3D_CLUSTER:-ti-k8s}"
K3D_CONTAINER="${K3D_CONTAINER:-k3d-${K3D_CLUSTER}-server-0}"
HELM_CHART="${HELM_CHART:-$ROOT/deploy/k8s/charts/ti-platform}"
HELM_VALUES_TRIAL="${HELM_VALUES_TRIAL:-$HERE/packer/files/values-trial-ova.yaml}"

# Log-line prefix the API progress poller scrapes.
log() { printf '[ova-builder] %s\n' "$*"; }

# ── Slug helper ──────────────────────────────────────────────────────────────
# "ACME Corp <eval@acme.com>" → "acme-corp"
slugify() {
    echo "$1" \
        | sed -E 's/<[^>]*>//g' \
        | tr '[:upper:]' '[:lower:]' \
        | sed -E 's/[^a-z0-9]+/-/g; s/^-+|-+$//g' \
        | head -c 40
}

SLUG=$(slugify "$CUSTOMER")
[ -n "$SLUG" ] || { echo "could not derive slug from customer name: $CUSTOMER" >&2; exit 2; }

OVA_BASENAME="ti-platform-trial-${SLUG}-${DAYS}d"
OUT_OVA="$DIST_DIR/${OVA_BASENAME}.ova"

echo "════════════════════════════════════════════════════════════════"
echo "  build-trial-ova"
echo "    customer:        $CUSTOMER"
echo "    slug:            $SLUG"
echo "    days:            $DAYS"
echo "    license features: $FEATURES"
if [ ${#ENABLED_FEATURES[@]} -gt 0 ] || [ ${#DISABLED_FEATURES[@]} -gt 0 ]; then
    echo "    modular features:"
    echo "      enabled:       ${ENABLED_FEATURES[*]:-(none)}"
    echo "      disabled:      ${DISABLED_FEATURES[*]:-(none)}"
fi
echo "    output:          $OUT_OVA"
echo "════════════════════════════════════════════════════════════════"

# ── Prereq checks ────────────────────────────────────────────────────────────
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }; }
need qemu-img
need virt-customize
need python3
need tar
need sha256sum
need sed

[ -f "$GOLDEN_DISK"     ] || { echo "golden disk not found: $GOLDEN_DISK" >&2; echo "  Build it first:  cd $HERE/packer && ./build.sh" >&2; exit 1; }
[ -f "$LICENSE_GEN"     ] || { echo "license-gen not found: $LICENSE_GEN" >&2; exit 1; }
[ -f "$LICENSE_PRIV_KEY" ] || { echo "private key not found: $LICENSE_PRIV_KEY" >&2; echo "  Generate one:  python $LICENSE_GEN --gen-key" >&2; exit 1; }
[ -f "$OVF_TEMPLATE"    ] || { echo "OVF template not found: $OVF_TEMPLATE" >&2; exit 1; }

# ── Workspace ────────────────────────────────────────────────────────────────
WORK=$(mktemp -d -t ti-ova-XXXXXX)
trap 'rm -rf "$WORK"' EXIT
echo "  workdir:   $WORK"

mkdir -p "$DIST_DIR"

# libguestfs (used by virt-customize below) tries to stat
# /var/tmp/.guestfs-<uid> on init.  When this script runs inside the
# ti-api pod (UID 10001), /var/tmp is read-only, so we point libguestfs
# at $TMPDIR instead and pre-create the per-uid cache dir it expects.
export TMPDIR="${TMPDIR:-/tmp}"
export LIBGUESTFS_CACHEDIR="$TMPDIR/libguestfs-cache"
export LIBGUESTFS_TMPDIR="$TMPDIR/libguestfs-tmp"
mkdir -p "$LIBGUESTFS_CACHEDIR" "$LIBGUESTFS_TMPDIR"

# ── kubectl / helm helpers ───────────────────────────────────────────────────
# All cluster ops route through the k3d server container so the script
# works identically inside the API pod (which doesn't have a kubeconfig
# pointing at the trials k3d) and from a dev shell (which usually does).
k()    { docker exec "$K3D_CONTAINER" kubectl "$@"; }
helm() { docker exec "$K3D_CONTAINER" helm    "$@"; }

# ── 0. Stage service images into the build k3d cluster ───────────────────────
# Folds in .tmp/ship_images_to_trial.py.  When STAGE_IMAGES=1, export each
# service image from the host docker daemon and import it into the build
# k3d cluster so the trial-image pipeline can find them locally instead
# of trying to pull from docker.io.
SERVICE_IMAGES=(
    "ti-platform/api:1.0.0"
    "ti-platform/frontend:1.0.0"
    "ti-platform/correlation:1.0.0"
    "ti-platform/url-intel:1.0.0"
    "ti-platform/web-content-analyzer:1.0.0"
)

stage_images() {
    log "── 0. stage service images into k3d cluster '$K3D_CLUSTER' ──"
    command -v docker >/dev/null 2>&1 || { log "  docker missing; cannot stage images"; return 1; }
    command -v k3d    >/dev/null 2>&1 || { log "  k3d missing;    cannot stage images"; return 1; }

    local img tar safe
    for img in "${SERVICE_IMAGES[@]}"; do
        if ! docker image inspect "$img" >/dev/null 2>&1; then
            log "  skip (not in local docker): $img"
            continue
        fi
        safe=$(printf '%s' "$img" | tr '/:' '__')
        tar="$TMPDIR/${safe}.tar"
        log "  docker save  $img -> $(basename "$tar")"
        docker save -o "$tar" "$img"
        log "  k3d   import $img"
        k3d image import "$tar" -c "$K3D_CLUSTER"
        rm -f "$tar"
    done
    log "  image staging done"
}

# ── 0.5. Phase-1 ordering: postgres + redis first, then helm install ─────────
# Folds in .tmp/trial_phase1_pg_redis.py.  When STAGE_PHASE1=1, install
# only postgresql + redis via helm, wait for them to be Ready, THEN do a
# full helm upgrade --install of the rest.  Matches the trial-VM firstboot
# ordering that fixed the api-can't-connect-to-postgres race we hit
# during the May builds.
stage_phase1() {
    log "── 0.5. phase-1: stand up postgres + redis, then helm install ──"

    k create namespace ti --dry-run=client -o yaml | k apply -f -

    # Phase 1: data-layer subcharts only — every ti-platform service
    # template disabled so this pass only renders postgres + redis.
    log "  helm install (phase-1: postgresql + redis only)"
    local phase1_disables=(api frontend correlation ingestion enrichment
                           icap logserver sandbox nats)
    local set_flags=(--set postgresql.enabled=true --set redis.enabled=true)
    for svc in "${phase1_disables[@]}"; do
        set_flags+=(--set "${svc}.enabled=false")
    done
    helm upgrade --install ti "$HELM_CHART" \
        --namespace ti \
        --values "$HELM_VALUES_TRIAL" \
        "${set_flags[@]}" \
        --wait --timeout 5m || log "  WARN: phase-1 helm did not converge"

    log "  waiting for postgres Ready"
    k -n ti wait --for=condition=ready pod \
        -l app.kubernetes.io/name=postgresql --timeout=300s || true

    log "  waiting for redis Ready"
    k -n ti wait --for=condition=ready pod \
        -l app.kubernetes.io/name=redis --timeout=180s || true

    # Phase 2: full chart, NATS overlay (single replica, jetstream off)
    # inherited from values-trial-ova.yaml.
    log "  helm install (phase-2: full chart)"
    helm upgrade --install ti "$HELM_CHART" \
        --namespace ti \
        --values "$HELM_VALUES_TRIAL" \
        --wait --timeout 10m || \
        log "  WARN: full helm install did not converge; continuing"
}

# ── Two-phase Postgres dump/restore helper ───────────────────────────────────
# Folds in .tmp/fix_trial_v3_schema.py.  Split the dump so we don't repeat
# the v3 mistake where a data-only restore ran against an empty schema
# (every COPY failed silently -> API 500s).  Schema-only first, then
# pg_restore --data-only on top.
#
# Usage:
#   pg_two_phase_dump_restore <src_pod> <src_ns> <dst_pod> <dst_ns> <db> <pg_pass>
pg_two_phase_dump_restore() {
    local src_pod=$1 src_ns=$2 dst_pod=$3 dst_ns=$4 db=$5 pgpass=$6
    local schema="$TMPDIR/${db}-schema.sql"
    local data="$TMPDIR/${db}-data.dump"

    # Shorthand: run a pg_* / psql command inside a pod with the env+user
    # boilerplate filled in.  Stdout flows back to the caller's redirect.
    pg_in() {
        local ns=$1 pod=$2; shift 2
        k -n "$ns" exec "$pod" -- env "PGPASSWORD=$pgpass" "$@" -U postgres -d "$db"
    }

    log "  phase A: pg_dump --schema-only from $src_ns/$src_pod"
    pg_in "$src_ns" "$src_pod" pg_dump \
        --schema-only --no-owner --no-privileges --no-tablespaces > "$schema"
    [ -s "$schema" ] || { log "  ERROR: schema dump empty"; return 1; }

    log "  phase B: pg_dump --data-only (custom format)"
    pg_in "$src_ns" "$src_pod" pg_dump \
        --data-only --no-owner --no-privileges --format=custom > "$data"

    log "  restore A: apply schema-only to $dst_ns/$dst_pod"
    k -n "$dst_ns" cp "$schema" "$dst_pod:/tmp/schema.sql"
    pg_in "$dst_ns" "$dst_pod" psql -v ON_ERROR_STOP=0 -q -f /tmp/schema.sql

    log "  restore B: pg_restore --data-only"
    k -n "$dst_ns" cp "$data" "$dst_pod:/tmp/data.dump"
    pg_in "$dst_ns" "$dst_pod" pg_restore --data-only --no-owner /tmp/data.dump

    rm -f "$schema" "$data"
}

if [ "$STAGE_IMAGES" = "1" ]; then
    stage_images
fi
if [ "$STAGE_PHASE1" = "1" ]; then
    stage_phase1
fi

# ── 1. Mint the license ──────────────────────────────────────────────────────
echo
echo "── 1. mint license ──"
LICENSE_JWS="$WORK/license.jws"
python3 "$LICENSE_GEN" \
    --customer "$CUSTOMER" \
    --days     "$DAYS" \
    --features "$FEATURES" \
    --priv-key "$LICENSE_PRIV_KEY" \
    --out      "$LICENSE_JWS"
[ -s "$LICENSE_JWS" ] || { echo "license-gen produced an empty file" >&2; exit 1; }

# Extract license_id for the OVF description (informational only).
LICENSE_ID=$(python3 -c "
import sys, base64, json
parts = open(sys.argv[1], 'rb').read().strip().split(b'.')
pad = b'=' * (-len(parts[1]) % 4)
print(json.loads(base64.urlsafe_b64decode(parts[1] + pad))['license_id'])
" "$LICENSE_JWS")

# ── 2. Linked clone ──────────────────────────────────────────────────────────
echo
echo "── 2. linked-clone golden disk ──"
CLONE="$WORK/customer.qcow2"
qemu-img create -f qcow2 -F qcow2 -b "$GOLDEN_DISK" "$CLONE" >/dev/null
echo "  cloned $(basename "$GOLDEN_DISK") → $(basename "$CLONE")  ($(du -h "$CLONE" | cut -f1))"

# ── 3. Inject license + customer hostname (virt-customize, no boot) ─────────
echo
echo "── 3. inject license + per-customer hostname ──"
VC_HOSTNAME="ti-platform-${SLUG:0:30}"     # k8s-style hostnames cap at 63

# Build the modular-feature overlay that ti-firstboot.sh layers onto
# values-trial-ova.yaml at install time.  When no --features / FEATURES
# (modular) was requested we ship only a marker comment so firstboot
# detects "no overlay → keep defaults" without a missing-file branch.
VC_EXTRA_COPY_IN=()
if [ ${#ENABLED_FEATURES[@]} -gt 0 ] || [ ${#DISABLED_FEATURES[@]} -gt 0 ]; then
    FEATURES_YAML="$WORK/values-features.yaml"
    {
        echo "# Auto-generated by build-trial-ova.sh — modular-OVA feature overlay."
        echo "# Customer: $CUSTOMER ($SLUG)"
        echo "# Built:    $(date -Is)"
        echo "# Enabled:  ${ENABLED_FEATURES[*]:-(none)}"
        echo "# Disabled: ${DISABLED_FEATURES[*]:-(none)}"
        for c in "${ENABLED_FEATURES[@]}";  do printf '%s:\n  enabled: true\n'  "$c"; done
        for c in "${DISABLED_FEATURES[@]}"; do printf '%s:\n  enabled: false\n' "$c"; done
    } > "$FEATURES_YAML"
    VC_EXTRA_COPY_IN+=(--copy-in "$FEATURES_YAML:/opt/ti-platform/etc/")

    # Greppable log: the API progress poller and the firstboot script
    # both check this file rather than re-parse the YAML.
    HELM_FLAGS_FILE="$WORK/helm-feature-sets.txt"
    printf '%s\n' "${HELM_FEATURE_FLAGS[@]}" > "$HELM_FLAGS_FILE"
    VC_EXTRA_COPY_IN+=(--copy-in "$HELM_FLAGS_FILE:/opt/ti-platform/etc/")
fi

virt-customize -a "$CLONE" \
    --hostname  "$VC_HOSTNAME" \
    --copy-in   "$LICENSE_JWS:/etc/ti-platform/" \
    "${VC_EXTRA_COPY_IN[@]}" \
    --run-command "chmod 0644 /etc/ti-platform/license.jws" \
    --run-command "chown root:root /etc/ti-platform/license.jws" \
    >/dev/null
# (Removed an extra `mv` step: $LICENSE_JWS is always named license.jws,
#  and `mv X X` errors with "same file".  The --copy-in already lands the
#  file at /etc/ti-platform/license.jws.)
echo "  hostname:  $VC_HOSTNAME"
echo "  license:   /etc/ti-platform/license.jws  (id $LICENSE_ID)"
if [ ${#VC_EXTRA_COPY_IN[@]} -gt 0 ]; then
    echo "  features:  /opt/ti-platform/etc/values-features.yaml"
fi

# ── 4. qcow2 → VMDK streamOptimized ──────────────────────────────────────────
echo
echo "── 4. convert qcow2 → VMDK streamOptimized ──"
VMDK="$WORK/disk.vmdk"
qemu-img convert -p -O vmdk -o subformat=streamOptimized "$CLONE" "$VMDK"
DISK_SIZE=$(stat -c %s "$VMDK")
CAPACITY=$(qemu-img info --output=json "$CLONE" | python3 -c "import json,sys; print(json.load(sys.stdin)['virtual-size'])")
POPULATED=$(qemu-img info --output=json "$CLONE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('actual-size', d['virtual-size']))")
echo "  vmdk size:    $(numfmt --to=iec --suffix=B "$DISK_SIZE")  ($DISK_SIZE bytes)"
echo "  capacity:     $(numfmt --to=iec --suffix=B "$CAPACITY")"
echo "  populated:    $(numfmt --to=iec --suffix=B "$POPULATED")"

# ── 5. Render OVF from template ──────────────────────────────────────────────
echo
echo "── 5. render OVF descriptor ──"
OVF="$WORK/${OVA_BASENAME}.ovf"
DESCRIPTION="TI Platform — ${DAYS}-day trial.  Issued to: ${CUSTOMER}.  License ID: ${LICENSE_ID}.  Default URL after boot: http://<vm-ip>:30080"

# OVF/XML is sensitive to & < > inside attribute / element values — escape.
xml_escape() {
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

VM_NAME_ESC=$(printf '%s' "TI Platform Trial — ${CUSTOMER}" | xml_escape)
DESC_ESC=$(   printf '%s' "$DESCRIPTION"                    | xml_escape)

sed -e "s|@VM_NAME@|${VM_NAME_ESC//|/\\|}|g" \
    -e "s|@DESCRIPTION@|${DESC_ESC//|/\\|}|g" \
    -e "s|@DISK_FILE@|disk.vmdk|g" \
    -e "s|@DISK_SIZE@|${DISK_SIZE}|g" \
    -e "s|@CAPACITY@|${CAPACITY}|g" \
    -e "s|@POPULATED@|${POPULATED}|g" \
    "$OVF_TEMPLATE" > "$OVF"

# Sanity: descriptor must contain the substituted disk size, not the placeholder.
grep -q "@DISK_SIZE@" "$OVF" && { echo "OVF still has placeholders — sed failed" >&2; exit 1; }
echo "  $(basename "$OVF") — $(stat -c %s "$OVF") bytes"

# ── 6. Manifest (.mf) ────────────────────────────────────────────────────────
echo
echo "── 6. manifest (sha256) ──"
MF="$WORK/${OVA_BASENAME}.mf"
(
    cd "$WORK"
    {
        printf 'SHA256(%s)= %s\n' "$(basename "$OVF")" "$(sha256sum "$(basename "$OVF")" | cut -d' ' -f1)"
        printf 'SHA256(%s)= %s\n' "disk.vmdk"          "$(sha256sum disk.vmdk | cut -d' ' -f1)"
    } > "$MF"
)
cat "$MF"

# ── 7. Pack into OVA (pure-tar, OVF-spec ordering) ───────────────────────────
echo
echo "── 7. pack OVA ──"
# OVF spec (CSP1 / DSP0243) requires:
#   - the .ovf file as the FIRST entry in the tar
#   - the .mf file second (if present)
#   - disk files after
# tar honours the order of files passed on the command line.
(
    cd "$WORK"
    tar -cf "$OUT_OVA" \
        "${OVA_BASENAME}.ovf" \
        "${OVA_BASENAME}.mf" \
        "disk.vmdk"
)

# ── 8. Done ──────────────────────────────────────────────────────────────────
echo
echo "════════════════════════════════════════════════════════════════"
echo "  Built: $OUT_OVA"
echo "  Size:  $(du -h "$OUT_OVA" | cut -f1)"
echo "  License id: $LICENSE_ID"
echo "  Trial: $DAYS days for $CUSTOMER"
echo
echo "  Customer instructions:"
echo "    1. Import the .ova into VirtualBox / VMware Workstation / ESXi"
echo "    2. Start the VM (first boot takes ~3 min — k3s + helm install)"
echo "    3. Browse to  http://<vm-ip>:30080"
echo "    4. Trial expires in $DAYS days; the in-app /license page shows status"
echo "════════════════════════════════════════════════════════════════"
