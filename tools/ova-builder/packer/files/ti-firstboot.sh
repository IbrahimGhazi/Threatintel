#!/bin/bash
# /usr/local/sbin/ti-firstboot.sh  (installed by 04-vendor-platform.sh)
#
# Runs ONCE on the customer's first boot of the trial OVA.  Brings up
# k3s, deploys the helm chart, and waits for pods.  Subsequent boots
# short-circuit via the systemd unit's ConditionPathExists guard plus
# the marker file we touch at the end.
#
# Idempotent in case anything fails partway and systemd retries.
set -euo pipefail

MARKER=/var/lib/ti-platform/.firstboot-done
LOG=/var/log/ti-firstboot.log

# Tee everything to a log so a failed first boot is debuggable from the
# console (`cat /var/log/ti-firstboot.log`).
exec > >(tee -a "$LOG") 2>&1

if [ -f "$MARKER" ]; then
    echo "[$(date -Is)] first-boot already completed; nothing to do"
    exit 0
fi

echo "[$(date -Is)] === ti-firstboot: starting ==="

# 1. Make sure the system has a unique machine-id (07-cleanup blanked it
#    at build, systemd usually regenerates on first boot — belt + braces
#    in case the cloud platform skipped it).
if [ ! -s /etc/machine-id ]; then
    echo "  generating machine-id"
    systemd-machine-id-setup
fi

# 2. Start k3s (installed at build time but disabled).  We enable +
#    start here so the customer VM owns its own k3s state from boot one.
echo "[$(date -Is)] enabling k3s"
systemctl enable --now k3s

# 3. Wait for the API server to come up.  k3s + the airgap-image import
#    typically takes 30-60s on first boot of a 4 vCPU VM.
echo "[$(date -Is)] waiting for k3s API"
for i in $(seq 1 60); do
    if /usr/local/bin/kubectl get nodes >/dev/null 2>&1; then
        echo "  k3s ready after ${i}s"
        break
    fi
    sleep 1
done

# 4. Deploy the platform via helm.
echo "[$(date -Is)] helm install ti-platform"
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
/usr/local/bin/kubectl create namespace ti --dry-run=client -o yaml \
    | /usr/local/bin/kubectl apply -f -

# build-trial-ova.sh --features writes a per-build overlay into the qcow2
# at /opt/ti-platform/etc/values-features.yaml.  Layer it on top of the
# baseline values.yaml if present — later --values wins under helm's
# left-to-right merge, so feature-specific enabled flags take effect.
HELM_VALUES_ARGS=(--values /opt/ti-platform/etc/values.yaml)
if [ -f /opt/ti-platform/etc/values-features.yaml ]; then
    echo "  applying modular-feature overlay (values-features.yaml)"
    HELM_VALUES_ARGS+=(--values /opt/ti-platform/etc/values-features.yaml)
fi

/usr/local/bin/helm upgrade --install ti /opt/ti-platform/helm \
    --namespace ti \
    "${HELM_VALUES_ARGS[@]}" \
    --wait --timeout 10m

# 5. License bootstrap.  If the OVA-build pipeline injected a license
#    at /etc/ti-platform/license.jws, the API will pick it up at boot
#    via the LICENSE_FILE bootstrap path (see services/api/app/license/
#    state.py).  Nothing to do here — just sanity-log it.
if [ -f /etc/ti-platform/license.jws ]; then
    SIZE=$(stat -c %s /etc/ti-platform/license.jws)
    echo "[$(date -Is)] license file present ($SIZE bytes)"
else
    echo "[$(date -Is)] no license file — API will run unlicensed (dev mode)"
fi

# 6. Touch marker so we don't run again.
mkdir -p "$(dirname "$MARKER")"
date -Is > "$MARKER"

echo "[$(date -Is)] === ti-firstboot: done ==="
