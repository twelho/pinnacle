# pinnacle

> *The pinnacle of engineering edition™*

UEFI application in Rust that prompts for a boot-time PIN, extends a memory-hard and compute-hard hash of it into a TPM PCR via `EFI_TCG2_PROTOCOL`, then chainloads the next boot loader, which may live on a different volume. All while maintaining the Secure Boot trust chain.

The given **printable-character PIN** (not just numbers) is passed through Argon2id:

```text
measured = "pinnacle" || pcr_index_le || argon2id(pin_char16le, salt=smbios_uuid, params)
```

`pin_char16le` is the little-endian serialization of the UEFI `CHAR16` code units entered at the firmware text console. UEFI describes those code units as UCS-2; for valid BMP text this is byte-for-byte UTF-16LE.

Default behavior:

- PCR: `15`
- next image: `\EFI\boot\BOOTX64.efi` (the removable-media path)
- event log: no entry by default (extend-only)
- Argon2id: 64 MiB memory, 64 passes, 1 lane, 32-byte output

These are `const`s at the top of `src/main.rs`. The measured bytes carry no pinnacle version and do not include `NEXT_LOADER_PATH`, so upgrading pinnacle or retargeting the chainload does **not** move the PCR. Chainloading a stable removable path rather than a versioned image keeps it stable across kernel and loader upgrades too.

All prerequisites, including a present TPM with an active SHA-256 bank, a clean (all-zero) PIN target PCR, and a reachable next loader that passes Secure Boot verification, is checked before the prompt, so a misconfiguration never wastes a PIN entry. A non-zero PCR (e.g. a boot loop that re-entered pinnacle) aborts rather than extending twice. Any fatal condition prints why and reboots, rather than falling through to another boot entry, and `ESC` at the prompt aborts, also by rebooting.

> [!NOTE]
> The Argon2id salt is the machine's SMBIOS system UUID (the value Linux exposes as `/sys/devices/virtual/dmi/id/product_uuid`), read at boot, so each machine derives a distinct hash with no per-installation configuration. The salt is not secret (an attacker can read the UUID); its job is to prevent precomputed rainbow tables and cross-machine table reuse, not to resist a targeted brute force; that is the cost parameters' job. Firmware that reports no usable UUID (all-zero/all-`FF`) falls back to the `FALLBACK_SALT` const with a warning. Changing the effective salt or the cost parameters moves the PCR, so re-seal any bound secret afterwards.

> [!IMPORTANT]
> PCR choice: the default is PCR 15 ("system identity"), the least contended **non-resettable** slot: firmware owns 0-7, GRUB 8-9, IMA 10, systemd-stub 11-13, and shim 14 (so PCR 14 is occupied wherever shim runs, free only on shim-less stacks). pinnacle runs before any OS component, so PCR 15 starts at zero. The resettable PCRs 16 (debug) and 23 (application) are **avoided** because resettability would let an attacker retry PIN guesses without a reboot. Caveat: systemd reserves PCR 15 for machine/volume identity; do not also bind that on the same system. Confirm your pick reads all-zero after a normal boot (`tpm2_pcrread sha256:15`, `systemd-analyze pcrs 15`) before sealing.

> [!IMPORTANT]
> TPM SHA-256 required: `hash_log_extend_event` extends every active PCR bank, so pinnacle checks the TCG2 capability and refuses to extend unless the SHA-256 bank is active. A TPM offering only SHA-1 (or with SHA-256 disabled) is rejected rather than binding a secret to a weak PCR. If the SHA-384 or SHA-512 banks are enabled, those will automatically be extended as well.

## Build

The target is `x86_64-unknown-uefi` (precompiled `core`/`alloc` ship with the stable toolchain, so no nightly or `build-std`). A host C compiler is needed only to build the proc-macro dependencies.

```bash
rustup target add x86_64-unknown-uefi
cargo build --release
```

Output: `target/x86_64-unknown-uefi/release/pinnacle.efi`

## Test in QEMU

`./qemu` boots pinnacle in QEMU against an emulated TPM (`swtpm`), so you can exercise the whole flow without bare metal. It needs `bash`, `qemu-system-x86_64`, `swtpm`, `mtools`, OVMF firmware, and an x86_64 EFI image to use as the next loader. If `nix` is available, the script can fetch the QEMU tools, OVMF, and the EDK2 UEFI shell automatically. If not, it uses the tools and firmware installed by your distro. No root is needed; the FAT images are assembled with `mtools` and the TPM runs in userspace.

```bash
./qemu
```

The script auto-detects common distro OVMF and UEFI-shell paths. If your distro installs them elsewhere, point the script at them explicitly:

```bash
PINNACLE_OVMF_DIR=/usr/share/OVMF \
PINNACLE_NEXT_LOADER=/path/to/Shell.efi \
  ./qemu
```

Alternatively, set `PINNACLE_OVMF_CODE` and `PINNACLE_OVMF_VARS` instead of `PINNACLE_OVMF_DIR`. Set `PINNACLE_NO_NIX=1` to force native tooling even when `nix` is installed.

It lays out two virtual disks: pinnacle at `\EFI\boot\BOOTX64.efi` on the boot disk, and the UEFI shell (or `PINNACLE_NEXT_LOADER`) at the same path on a second disk to stand in for the real next loader. You should see the banner, the TPM checks and the loader being resolved, the PIN prompt, the PCR value before and after extending, and finally a drop into the `Shell>` prompt (the chainload target). Secure Boot is not enforced here, so the unsigned image boots.

Exit with `Ctrl-a x`, `Ctrl-c`, or press `ESC` at the PIN prompt; that reboots, and `-no-reboot` makes QEMU quit instead of looping. The full serial output is also written to `qemu-serial.log`; read it (or `tail -f` it) to see lines the chained loader wipes when it clears the screen, such as the debug PCR reads.

With the default cost parameters Argon2id is (intentionally) slow under QEMU's software emulation (TCG). Enable KVM (`/dev/kvm`) or temporarily lower `ARGON2_TIME` for quicker iteration.

## Sign for Secure Boot

pinnacle must be signed by a key whose certificate is enrolled in the Secure Boot `db`. `pki/sign.sh` checks that the key/cert are a pair, signs the image, and confirms a signature was embedded; it needs `openssl` and `sbsigntool` on `PATH`. The key/cert default to `db.key`/`db.crt` and can be overridden with `SB_KEY`/`SB_CERT`.

> `sign.sh` deliberately does not run a full `sbverify` cryptographic check. `sbverify` (via OpenSSL) enforces X.509 code-signing *purpose*, so it reports `Signature verification failed` for a `db` certificate that is a CA cert or otherwise lacks `keyUsage=digitalSignature`, the typical format of a Secure Boot `db` cert. This is a false negative: UEFI firmware does not apply that purpose check, so the image still boots. If your firmware already Secure-Boots an image signed with this key, it will accept pinnacle signed with it too.

**If you already have a Secure Boot PKI**, point `SB_KEY`/`SB_CERT` at your `db` signing pair:

```bash
cd pki
SB_KEY=your-db.key SB_CERT=your-db.crt \
  ./sign.sh ../target/x86_64-unknown-uefi/release/pinnacle.efi
```

**To create a fresh PKI from scratch**, `pki/gen-pki.sh` generates PK, KEK, and db keys plus the signed `.auth` enrollment files (needs `openssl`, `efitools`, `uuidgen`):

```bash
cd pki
./gen-pki.sh # -> PK/KEK/db .key .crt .esl .auth
./sign.sh ../target/x86_64-unknown-uefi/release/pinnacle.efi
```

Either way this writes `pinnacle.signed.efi` next to the input. Keep private keys out of the repo (`*.key` and `*.pem` are git-ignored).

### Enroll the PKI

In firmware setup, clear Secure Boot to Setup Mode, then enroll the auth files in order: `db.auth`, `KEK.auth`, `PK.auth` (enrolling PK last activates User Mode). Many firmwares accept the `.auth` files directly; from Linux you can use `efi-updatevar`:

```bash
efi-updatevar -f db.auth db
efi-updatevar -f KEK.auth KEK
efi-updatevar -f PK.auth PK
```

## Install pattern

pinnacle lives on its own dedicated EFI System Partition and is the firmware's boot entry. It searches every filesystem volume for `NEXT_LOADER_PATH`, trying other partitions before its own, so the OS-managed ESP is left untouched:

```text
pinnacle ESP (dedicated):
  EFI/boot/BOOTX64.efi            <- pinnacle, signed; firmware boot entry

OS ESP (separate partition):
  EFI/boot/BOOTX64.efi            <- next loader (systemd-boot, shim, …)
  EFI/Linux/*.efi                 <- kernel / UKI, selected by the loader
```

Because its own volume is tried last, pinnacle chainloads the real loader on the separate ESP; keep the next loader on a different partition, or pinnacle would find itself and fail due to double-extend. Register it either at the removable path `\EFI\boot\BOOTX64.efi` on its ESP, or at a custom path with `efibootmgr`:

```bash
efibootmgr --create --disk /dev/sda --part 1 \
  --loader '\EFI\pinnacle\pinnacle.efi' --label pinnacle
```

Order the firmware boot entries so pinnacle's partition is tried first.

> [!TIP]
> On machines whose firmware insists on preferring "Windows Boot Manager", another practical trick is to place the signed pinnacle image at `\EFI\Microsoft\Boot\bootmgfw.efi` on the pinnacle ESP and use that as the firmware-facing boot path. This only works around firmware boot-order behavior; pinnacle still chainloads `NEXT_LOADER_PATH` from the other volumes as usual. Do not overwrite a real Windows boot manager unless that is intentional and you have a backup. Also note that Windows might overwrite the `bootmgfw.efi` paths on upgrade if it feels like it.

pinnacle and every image it leads to must be signed by your `db` key for Secure Boot to load them. `NEXT_LOADER_PATH` defaults to `\EFI\boot\BOOTX64.efi`, the removable-media path, and is changed by editing that one `const`.

> [!IMPORTANT]
> `shim` (used by most Secure Boot distributions) treats being launched from the removable-media path `\EFI\boot\BOOTX64.efi` as a first-boot signal and runs `fbx64.efi`, which recreates the firmware boot entries and reboots ("Reset System") instead of chainloading GRUB. So point `NEXT_LOADER_PATH` at the *installed* loader, such as `\EFI\ubuntu\shimx64.efi`, which keeps the Secure Boot chain and hands off to GRUB normally because shim launched from there is not a removable path, or `\EFI\ubuntu\grubx64.efi` to skip shim entirely (Secure Boot off only, as GRUB is not signed for `db`). Self-contained loaders like systemd-boot have no such behavior and chainload fine from the removable path.

## Verify after booting Linux

```bash
systemd-analyze pcrs 15
# or
sudo tpm2_pcrread sha256:15
```

If you built with the `debug-event-log` feature (`cargo build --release --features debug-event-log`), pinnacle's extend is recorded in the event log, which you can inspect:

```bash
sudo tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements | less
```

By default that feature is off, so pinnacle's extend is not recorded in the event log. That is least disclosure rather than a security boundary; the resulting PCR value is world-readable regardless.

## Security model and limits

pinnacle adds a PIN factor by extending it into a PCR that, for example, disk encryption is then sealed to. Binding to an arbitrary PCR is the only lever available without OS support for a TPM PIN (authValue), but it has hard limits worth understanding:

- **No dictionary-attack lockout.** TPM objects sealed to a PCR policy get no TPM lockout; that only applies to authValue-based auth, which is not used here. Guessing is limited only by how fast an attacker can drive the TPM through a reset + extend + unseal cycle, or crack the PIN offline from an observed PCR value. The Argon2id pass raises the per-guess cost from a single SHA-256 to a memory-hard and compute-hard hash (64 MiB, 64 passes, GPU/ASIC-resistant) and the salt defeats precomputed tables, but a *low-entropy* PIN is still crackable given enough attacker compute. **PIN entropy remains the actual defense: treat it as a passphrase, not a numeric PIN.**
- **TPM bus sniffing.** On a discrete (SPI/LPC) TPM the unsealed key crosses the bus in the clear once the correct PIN reproduces the PCR; the PIN does not protect against an interposer/sniffer. Prefer a firmware TPM (fTPM).
- **Evil-maid resistance requires enforced Secure Boot.** To prevent an attacker from replacing pinnacle with a PIN stealer, pinnacle must be signed by a key you control and Secure Boot must be enabled and enforced. The chainloaded boot loader must also be signed. This is intentional: pinnacle is not `shim` and does not perform its own image validation. It asks firmware to load the next image, so the normal firmware Secure Boot policy verifies the next boot loader during `LoadImage`.
- **Lock the firmware.** Set a firmware admin password and lock the Secure Boot configuration so an attacker cannot disable Secure Boot or enroll their own keys to run PIN-stealing or brute-force tooling.
- **Cross-machine portability is handled primarily by the TPM.** A key sealed to a TPM is encrypted under that TPM's storage root key and cannot be unsealed on another (or emulated) TPM, so moving the *disk* to different hardware, or replaying observed PCR values on a bench `swtpm`, already fails regardless of the PIN. pinnacle also uses the SMBIOS system UUID as the public Argon2id salt, which changes the derived measurement across machines, but that is for table resistance and cross-machine precomputation resistance, not a trusted machine-binding mechanism.

Lastly, pinnacle is not equivalent to `systemd-cryptenroll --tpm2-with-pin=yes`, which binds the PIN as a TPM authValue and gets real lockout; pinnacle binds to a PCR precisely for stacks that lack that path or do not want to use it for some reason (you should if you can).

## Author

- Dennis Marttinen ([@twelho](https://github.com/twelho))

## License

[MPL-2.0](https://spdx.org/licenses/MPL-2.0.html) ([LICENSE](LICENSE))
