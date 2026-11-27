#!/usr/bin/env bash
set -euo pipefail

VERSION=""

usage() {
  echo "Usage: $0 -v <version>"
  echo "Example: $0 -v v1.2.3"
}

while getopts ":v:h" opt; do
  case "$opt" in
    v)
      VERSION="$OPTARG"
      ;;
    h)
      usage
      exit 0
      ;;
    :)
      echo "Error: Option -$OPTARG requires an argument." >&2
      usage >&2
      exit 1
      ;;
    \?)
      echo "Error: Invalid option -$OPTARG" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  echo "Error: Version is required." >&2
  usage >&2
  exit 1
fi

# Remove an optional leading v (v1.2.3 -> 1.2.3).
VERSION="${VERSION#v}"

# Validate the semantic version.
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "Error: Invalid semantic version: $VERSION" >&2
  exit 1
fi

echo "Releasing version: $VERSION"

# Update and validate Cargo.toml files.
for f in Cargo.toml common/Cargo.toml; do
  if [[ ! -f "$f" ]]; then
    echo "Error: Expected $f to exist; aborting release." >&2
    exit 1
  fi

  sed -i.bak "s|^version = \".*\"|version = \"$VERSION\"|" "$f"
  rm -f "$f.bak"

  actual="$(grep -m1 '^version = ' "$f" | cut -d'"' -f2)"

  if [[ "$actual" != "$VERSION" ]]; then
    echo "Error: $f version did not update to $VERSION (got: $actual)" >&2
    exit 1
  fi

  echo "Stamped $f -> $actual"
done

echo "All files updated to version $VERSION"
