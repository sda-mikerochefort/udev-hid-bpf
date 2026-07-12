#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Usage: check-bpf-files.sh <builddir>
#
# Check that all .bpf.c files tracked in git under
# src/bpf/{stable,testing,userhacks} have a corresponding
# .bpf.o target in the meson build.
#
# The builddir must have been configured with
#   meson setup <builddir> -Dbpfs=stable,testing,userhacks

set -euo pipefail

usage () {
  # Prints anything from the first line that is '#\n' to the first empty line
  sed -n '/^#$/ { :a; n; /^$/q; s/^#[ ]\?//p; ba }' "${BASH_SOURCE[0]}"
}

if [ $# -ne 1 ]; then
    usage
    exit 2
fi

builddir="$1"

if [ ! -d "$builddir" ]; then
    echo "ERROR: builddir '$builddir' does not exist"
    exit 2
fi

top_srcdir=$(git rev-parse --show-toplevel)

# Collect all .bpf.o target names from meson introspect.
# The tracing variants (e.g. 0009- for a 0010- source) are harmless
# duplicates here, we just need to check that each .bpf.c has at
# least one matching .bpf.o.
mapfile -t meson_targets < <(
    meson introspect --targets "$builddir" |
        jq -r '.[].name | select(endswith(".bpf.o"))' |
        sort -u
)

rc=0
errors=()

for section in stable testing userhacks; do
    section_dir="$top_srcdir/src/bpf/$section"

    # All .bpf.c files tracked by git in this section
    mapfile -t git_files < <(
        git ls-files -- "$section_dir"/'*.bpf.c' |
            xargs -r -n1 basename |
            sort -u
    )

    for bpf_c in "${git_files[@]}"; do
        expected="${bpf_c%.c}.o"

        found=0
        for target in "${meson_targets[@]}"; do
            if [ "$target" = "$expected" ]; then
                found=1
                break
            fi
        done

        if [ "$found" -eq 0 ]; then
            errors+=("$section/$bpf_c has no .bpf.o in meson build targets")
            rc=1
        fi
    done
done

if [ "$rc" -ne 0 ]; then
    echo "ERROR: .bpf.c files without matching .bpf.o meson targets:"
    echo
    for e in "${errors[@]}"; do
        echo "  $e"
    done
    exit 1
fi

echo "OK: all .bpf.c files have matching .bpf.o meson build targets"
exit 0
