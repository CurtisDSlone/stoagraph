#!/usr/bin/env bash
# tools/sbom.sh — a Software Bill of Materials for what we actually SHIP, plus a licence gate.
#
# A security control that cannot tell you what is inside it is asking for trust it has not earned.
#
# It scans the CONTAINER IMAGES, not the source tree — and that distinction matters. A dev's
# node_modules and the lockfile both contain `sharp` (LGPL-3.0), because npm resolves it as an optional
# transitive dep of Next. The console image does NOT: it is removed at build time, since the console
# never uses next/image. Scanning the source would therefore report a copyleft obligation that is not
# in the artifact, and scanning the artifact is the only thing that answers "what am I running?".
#
# The copyleft gate has already earned its keep — it is what surfaced that sharp was being shipped at
# all (33MB, LGPL, for a feature we do not use), and with it a build-context leak that was baking a
# developer's laptop node_modules into a published image.
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

OUT=sbom
BIN=.cache/bin
mkdir -p "$OUT" "$BIN"

SYFT="$(command -v syft || echo "$BIN/syft")"
if [ ! -x "$SYFT" ]; then
  echo "== fetching syft (once, into $BIN) =="
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b "$BIN" >/dev/null
  SYFT="$BIN/syft"
fi

IMAGES="stag-serve stag-proxy harness-serve"
missing=""
for i in $IMAGES; do
  docker image inspect "stoagraph-$i:latest" >/dev/null 2>&1 || missing="$missing $i"
done
if [ -n "$missing" ]; then
  echo "images not built:$missing"
  echo "  run: docker compose build"
  exit 1
fi

for i in $IMAGES; do
  printf '== %s ==\n' "$i"
  "$SYFT" scan "docker:stoagraph-$i:latest" -o cyclonedx-json --quiet -c .syft.yaml > "$OUT/$i.cdx.json"
done

echo
python3 - <<'PY'
import json, collections, pathlib, sys

# Copyleft that would encumber an Apache-2.0 product an enterprise wants to embed. LGPL is included
# deliberately: its dynamic-linking carve-out is often defensible, but it is an obligation a human must
# sign off on — so it stops the build and asks, rather than shipping quietly.
BLOCK = ("GPL-2", "GPL-3", "AGPL", "SSPL", "LGPL")

# The gate applies to OUR DEPENDENCY GRAPH — the Go modules and npm packages we chose and link against.
# It deliberately does NOT apply to base-image OS packages (apk/deb: busybox, libgcc, netbase...). GPL
# there is normal and is *mere aggregation*: we do not link against busybox, it is a separate program
# that happens to share a filesystem, and it imposes nothing on our code. Failing the build on those
# would be noise — and a check that cries wolf is a check people learn to skip, which is worse than no
# check at all.
APP = ("pkg:golang/", "pkg:npm/")

fail, total, os_copyleft = [], 0, 0
for p in sorted(pathlib.Path("sbom").glob("*.cdx.json")):
    b = json.loads(p.read_text())
    comps = b.get("components", [])
    total += len(comps)
    lic = collections.Counter()
    for c in comps:
        purl = str(c.get("purl") or "")
        is_ours = purl.startswith(APP)
        ls = c.get("licenses") or []
        if not ls:
            lic["(undeclared)"] += 1
        for l in ls:
            lo = l.get("license") or {}
            v = str(lo.get("id") or lo.get("name") or l.get("expression") or "")
            lic[v] += 1
            if any(k in v.upper() for k in BLOCK):
                if is_ours:
                    fail.append(f"{p.stem}: {c.get('name')}@{c.get('version')} -> {v}")
                else:
                    os_copyleft += 1
    top = ", ".join(f"{l}:{n}" for l, n in lic.most_common(4) if l)
    print(f"  {p.stem:16} {len(comps):4} components   {top}")

print(f"\n  {total} components across the shipped images")
print(f"  {os_copyleft} copyleft OS/base-image packages (mere aggregation — not an obligation on our code)")

if fail:
    print("\n  COPYLEFT IN OUR OWN DEPENDENCY GRAPH — this product is Apache-2.0.")
    print("  A human must decide this, not a build:")
    for f in fail:
        print(f"      {f}")
    sys.exit(1)
print("  no GPL/AGPL/SSPL/LGPL in any dependency we link ✓")
PY
echo
echo "wrote $OUT/*.cdx.json (CycloneDX)"
