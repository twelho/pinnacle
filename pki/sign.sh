#!/bin/sh -Eeu
set -o pipefail

_key=${SB_KEY:-db.key}
_cert=${SB_CERT:-db.crt}
_in=${1:?usage: [SB_KEY=key SB_CERT=cert] sign.sh INPUT.efi [OUTPUT.efi]}
_out=${2:-${_in%.efi}.signed.efi}

[ "$(openssl pkey -in "$_key" -pubout)" = "$(openssl x509 -in "$_cert" -noout -pubkey)" ] || \
	{ echo "error: $_key and $_cert are not a matching pair" >&2; exit 1; }

sbsign --key "$_key" --cert "$_cert" --output "$_out" "$_in"
sbverify --list "$_out" >/dev/null
echo "signed -> $_out"
