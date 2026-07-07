#!/bin/sh -Eeu
set -o pipefail

_guid=$(uuidgen)
for _n in PK KEK db; do
	openssl req -newkey rsa:4096 -nodes -keyout "$_n.key" -new -x509 -sha256 -days 3650 -subj "/CN=pinnacle $_n/" -out "$_n.crt"
	cert-to-efi-sig-list -g "$_guid" "$_n.crt" "$_n.esl"
done

sign-efi-sig-list -g "$_guid" -k PK.key -c PK.crt PK PK.esl PK.auth
sign-efi-sig-list -g "$_guid" -k PK.key -c PK.crt KEK KEK.esl KEK.auth
sign-efi-sig-list -g "$_guid" -k KEK.key -c KEK.crt db db.esl db.auth
