#!/usr/bin/env bash
# Generate a local Android release JKS and print the GitHub Actions secrets to set.
# Does not upload secrets (gh write is out of scope); copy the values into the repo settings.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/release.jks}"
ALIAS="${ANDROID_KEY_ALIAS:-kotlintor}"
VALIDITY_DAYS="${ANDROID_KEY_VALIDITY_DAYS:-10950}"

if [[ -e "$OUT" ]]; then
  echo "Refusing to overwrite existing $OUT" >&2
  exit 1
fi

read -r -s -p "Keystore password: " STORE_PASS
echo
read -r -s -p "Key password (empty = same as keystore): " KEY_PASS
echo
if [[ -z "$KEY_PASS" ]]; then
  KEY_PASS="$STORE_PASS"
fi

dname="${ANDROID_KEY_DNAME:-CN=kotlin-tor demo, OU=LTechnologies, O=LTechnologies, C=FR}"

keytool -genkeypair -v \
  -keystore "$OUT" \
  -storetype JKS \
  -keyalg RSA \
  -keysize 2048 \
  -validity "$VALIDITY_DAYS" \
  -alias "$ALIAS" \
  -storepass "$STORE_PASS" \
  -keypass "$KEY_PASS" \
  -dname "$dname"

props="$ROOT/keystore.properties"
if [[ ! -e "$props" ]]; then
  cat > "$props" <<EOF
storeFile=${OUT#"$ROOT/"}
storePassword=${STORE_PASS}
keyAlias=${ALIAS}
keyPassword=${KEY_PASS}
EOF
  echo "Wrote $props (gitignored)."
fi

echo
echo "Local signed APK:"
echo "  ./gradlew :demo-android:assembleRelease -Pkotlin.tor.extras=true"
echo
echo "GitHub repository secrets (Settings → Secrets and variables → Actions):"
echo "  ANDROID_KEYSTORE_BASE64   = base64 of $OUT (no newlines)"
echo "  ANDROID_KEYSTORE_PASSWORD = (the keystore password you entered)"
echo "  ANDROID_KEY_ALIAS         = $ALIAS"
echo "  ANDROID_KEY_PASSWORD      = (optional if identical to the keystore password)"
echo
if base64 --help 2>&1 | grep -q -- '-w'; then
  echo "Encode keystore:"
  echo "  base64 -w0 $(printf '%q' "$OUT")"
else
  echo "Encode keystore:"
  echo "  base64 $(printf '%q' "$OUT") | tr -d '\\n'"
fi
