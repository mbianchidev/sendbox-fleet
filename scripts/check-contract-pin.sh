#!/usr/bin/env bash
# Fails unless every SendBox crate is locked to a sendbox `main` commit.
#
# While a sendbox pull request is in review, a fleet pull request may track
# its branch (docs/contract.md). CI runs this check so such a pull request
# cannot merge until it tracks `main` again. Local path patches fail too.
set -euo pipefail

cd "$(dirname "$0")/.."
repo='https://github.com/sendbox-dev/sendbox'
status=0

while IFS= read -r line; do
  if [[ "$line" != *'branch = "main"'* || "$line" == *'rev ='* || "$line" == *'tag ='* ]]; then
    echo "Cargo.toml: SendBox dependency must use branch = \"main\": $line" >&2
    status=1
  fi
done < <(grep -F "git = \"$repo\"" Cargo.toml || true)

awk -v want="git+$repo?branch=main#" '
  function check() {
    if (name !~ /^sendbox-/) return
    found++
    hash = substr(source, length(want) + 1)
    if (index(source, want) != 1 || hash !~ /^[0-9a-f]+$/ || length(hash) != 40) {
      printf "Cargo.lock: %s is locked to %s, not a sendbox main commit\n",
        name, (source == "" ? "a local path" : source) > "/dev/stderr"
      bad = 1
    }
  }
  /^\[\[package\]\]$/ { check(); name = ""; source = ""; next }
  /^name = /   { name = $3; gsub(/"/, "", name) }
  /^source = / { source = $3; gsub(/"/, "", source) }
  END {
    check()
    if (found == 0) {
      print "Cargo.lock: no SendBox crates found" > "/dev/stderr"
      bad = 1
    }
    exit bad
  }
' Cargo.lock || status=1

if [[ "$status" -ne 0 ]]; then
  echo "Track sendbox main before merging: set branch = \"main\" in Cargo.toml, then run" >&2
  echo "  cargo update -p sendbox-governance -p sendbox-security" >&2
  exit 1
fi
echo "SendBox contract crates are locked to sendbox main."
