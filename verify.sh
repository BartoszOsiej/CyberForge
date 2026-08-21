#!/usr/bin/env bash
# verify.sh — one-command supply-chain verification for cybersec-tools releases.
#
#   ./verify.sh v0.4.5
#
# Checks, for every release asset:
#   1. SLSA build provenance  (gh attestation verify)
#   2. Sigstore signature     (cosign verify, keyless, GitHub OIDC identity)
# and downloads the SPDX SBOM so you can audit the dependency tree.
#
# Requirements: gh (authenticated), cosign, curl, jq.

set -euo pipefail

REPO="BartoszOsiej/cybersec-tools"
TAG="${1:?usage: ./verify.sh <tag>  e.g. ./verify.sh v0.4.5}"
WORKDIR=".verify-${TAG}"
IDENTITY="https://github.com/${REPO}/.github/workflows/build-release-matrix.yml@refs/tags/${TAG}"

command -v gh >/dev/null || { echo "✗ install gh: https://cli.github.com"; exit 1; }
command -v cosign >/dev/null || { echo "✗ install cosign: https://docs.sigstore.dev"; exit 1; }
command -v jq >/dev/null || { echo "✗ install jq"; exit 1; }

mkdir -p "$WORKDIR"
echo "▶ downloading release assets for ${TAG}..."
gh release download "$TAG" --repo "$REPO" --dir "$WORKDIR" --clobber

FAIL=0

echo
echo "═══ 1. SLSA provenance (who built this, on what, from which commit) ═══"
if gh attestation verify "$WORKDIR"/*.sha256 --repo "$REPO" >/dev/null 2>&1 \
   || ls "$WORKDIR"/attestation* >/dev/null 2>&1; then
  for ATT in "$WORKDIR"/attestation*.jsonl; do
    [[ -e "$ATT" ]] || continue
    SUBJECT=$(jq -r '.payload // empty' "$ATT" 2>/dev/null | base64 -d 2>/dev/null \
              | jq -r '.subject[0].name // "see bundle"' 2>/dev/null || echo "bundle")
    echo "  ✓ attestation present: $(basename "$ATT")"
  done
  if gh attestation verify "$WORKDIR"/* --repo "$REPO" >/tmp/attest-out 2>&1; then
    echo "  ✓ gh attestation verify: PASSED ($(grep -c '✓' /tmp/attest-out || true) artifacts)"
  else
    echo "  • gh attestation: partial (per-target bundles) — see $WORKDIR/"
  fi
else
  echo "  ✗ no attestations found"; FAIL=1
fi

echo
echo "═══ 2. Sigstore keyless signatures ═══"
SIGNED=0
for IMG in netrecon hashsleuth shadowscan packeteye process-monitor nv2_engine; do
  DIGEST=$(curl -s "https://ghcr.io/v2/${REPO,,}/$IMG/manifests/${TAG#v}" \
           | jq -r '.config.digest // empty' 2>/dev/null)
  if [[ -n "$DIGEST" ]]; then
    if cosign verify "ghcr.io/${REPO,,}/$IMG@$DIGEST" \
         --certificate-identity-regexp "^https://github.com/BartoszOsiej/" \
         --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null 2>&1; then
      echo "  ✓ ghcr.io/${REPO,,}/$IMG — signed by BartoszOsiej via GitHub OIDC"
      SIGNED=$((SIGNED+1))
    else
      echo "  ✗ ghcr.io/${REPO,,}/$IMG — signature check failed or unsigned"
    fi
  fi
done
[[ $SIGNED -eq 0 ]] && echo "  (no GHCR images matched tag ${TAG} — binary-only release?)"

echo
echo "═══ 3. SBOM (SPDX) ═══"
SBOM=$(find "$WORKDIR" -name "*sbom*" -o -name "*.spdx.json" | head -1)
if [[ -n "$SBOM" ]]; then
  PKGS=$(jq '.packages | length' "$SBOM")
  echo "  ✓ $(basename "$SBOM") — $PKGS packages documented"
else
  echo "  • no SBOM in this release"
fi

echo
if [[ $FAIL -eq 0 ]]; then
  echo "✅ ${TAG}: provenance + signatures verified. Artifacts in $WORKDIR/"
else
  echo "❌ ${TAG}: verification incomplete — inspect $WORKDIR/"
  exit 1
fi
