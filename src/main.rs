// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! pinnacle: a UEFI application that prompts for a boot PIN, extends a
//! memory-hard and compute-hard Argon2id hash of it into a TPM PCR, then
//! chainloads the next EFI loader (which may live on a different volume).
//! See the README for the security model and design.

#![no_main]
#![no_std]

extern crate alloc;

mod input;
#[macro_use]
mod log;
mod pcr;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;
use zeroize::Zeroizing;

use log::{Hex, Outcome};

use uefi::prelude::*;
use uefi::proto::console::text::Key;
use uefi::proto::device_path::build::{media::FilePath, DevicePathBuilder};
use uefi::proto::device_path::DevicePath;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::proto::tcg::v2::{HashLogExtendEventFlags, PcrEventInputs, Tcg};
use uefi::proto::tcg::{EventType, HashAlgorithm, PcrIndex};
use uefi::proto::BootPolicy;
use uefi::table::cfg::ConfigTableEntry;
use uefi::{cstr16, print, println, CStr16};

use argon2::{Algorithm, Argon2, Params, Version};

/// The next EFI image to chainload, searched for on every filesystem volume
/// (see `load_next`).
const NEXT_LOADER_PATH: &CStr16 = cstr16!("\\EFI\\boot\\BOOTX64.efi");

/// Non-resettable PCR the PIN measurement is extended into (see the README for
/// the choice of 15).
const PIN_PCR_INDEX: u32 = 15;

/// Maximum length of the PIN in UEFI CHAR16 (UCS-2/UTF-16) code units. There
/// is intentionally no minimum length, although PIN entropy is critical for
/// security (see the README).
const MAX_PIN_CHARS: usize = 128;

/// Domain separator prepended to the PIN-derived measurement.
const DOMAIN_PREFIX: &[u8] = b"pinnacle";

/// UEFI event log entry text if the `debug-event-log` feature is enabled.
const EVENT_TEXT: &[u8] = b"pinnacle secret PIN measurement was extended\0";

/// Salt used only when the machine reports no usable SMBIOS UUID (see
/// `pin_salt`). A warning will be issued before this is used.
const FALLBACK_SALT: &[u8] = b"pinnacle-of-engineering";

/// Argon2id cost parameters: memory in KiB, passes, and lanes (1, as UEFI is
/// single-threaded).
const ARGON2_MEM_KIB: u32 = 64 * 1024;
const ARGON2_TIME: u32 = 32;
const ARGON2_LANES: u32 = 1;

/// Length of the derived Argon2id key extended into the PCR. Matches SHA-256.
const PIN_HASH_LEN: usize = 32;

/// Secret buffer zeroized on drop. `zeroize` also clears a Vec's spare
/// capacity, so preallocating before writing secrets avoids leaving old
/// reallocations behind.
type Scrubbed<T> = Zeroizing<Vec<T>>;

#[entry]
fn main() -> Status {
    info!("pinnacle {} by twelho", env!("CARGO_PKG_VERSION"));

    match run() {
        Ok(()) => Status::SUCCESS,
        Err(fatal) => fatal.report(),
    }
}

fn run() -> Outcome {
    let next = prepare()?;

    info!("starting {}...", NEXT_LOADER_PATH);

    // Wait for a bit to ensure the final log messages can be read.
    boot::stall(Duration::from_secs(3));
    boot::start_image(next).map_err(Into::into)
}

/// Main pinnacle logic, this lives in a separate scope to make sure everything
/// that is not needed for chainloading is dropped before diverging.
fn prepare() -> Outcome<Handle> {
    // Everything that can fail runs before the prompt.
    let mut tcg = open_tpm()?;
    pcr::assert_clean(&mut tcg)?;
    let next = load_next()?;
    let uuid = read_smbios_uuid();
    let salt = pin_salt(uuid.as_ref());
    let pin = read_pin()?;
    extend_pin_to_pcr(&mut tcg, salt, &pin)?;
    Ok(next)
}

/// Acquire the TCG2 protocol and verify the TPM is present with an active
/// SHA-256 PCR bank.
fn open_tpm() -> Outcome<boot::ScopedProtocol<Tcg>> {
    let Ok(handle) = boot::get_handle_for_protocol::<Tcg>() else {
        fatal!(
            Status::NOT_FOUND,
            "no TCG2 protocol, is the TPM enabled in firmware?"
        );
    };
    let mut tcg = boot::open_protocol_exclusive::<Tcg>(handle)?;

    let capability = tcg.get_capability()?;
    if !capability.tpm_present() {
        fatal!(
            Status::NOT_FOUND,
            "TPM not present, enable it in firmware setup"
        );
    }

    // hash_log_extend_event extends every active PCR bank, so require SHA-256.
    // This is a reasonable assumption to avoid falling back to only SHA-1.
    if !capability.active_pcr_banks.contains(HashAlgorithm::SHA256) {
        fatal!(
            Status::SECURITY_VIOLATION,
            "SHA-256 PCR bank not active, enable it in firmware setup"
        );
    }

    Ok(tcg)
}

/// Read a PIN with echo masked by `*`. Returns the entered UEFI CHAR16
/// (UCS-2/UTF-16) code units.
fn read_pin() -> Outcome<Scrubbed<u16>> {
    info!("press ESC at the PIN prompt to abort");

    let prompt = format!("enter PIN to extend PCR[{}]: ", PIN_PCR_INDEX);
    prompt!("{prompt}");

    // Preallocate the maximum so entering the PIN cannot reallocate and leave
    // an unscrubbed copy of a prefix in an old heap allocation.
    let mut pin = Scrubbed::new(Vec::with_capacity(MAX_PIN_CHARS));
    let key_event = system::with_stdin(|stdin| stdin.wait_for_key_event())?;
    let mut events = [key_event];

    loop {
        boot::wait_for_event(&mut events).map_err(|e| e.status())?;

        let Some(key) = input::read_key()? else {
            continue;
        };

        match key {
            key if input::is_escape_key(key) => {
                if escape_aborts()? {
                    abort_from_prompt();
                }
            }
            Key::Printable(c) => match u16::from(c) {
                0x0d => {
                    println!();
                    // Ignore an empty entry so spamming enter just re-prompts.
                    if pin.is_empty() {
                        prompt!("{prompt}");
                        continue;
                    }
                    break;
                }
                0x08 => {
                    if !pin.is_empty() {
                        // Immediately zero any backspaced characters.
                        let last = pin.len() - 1;
                        pin[last] = 0;
                        pin.truncate(last);

                        // Yes, this does what you expect.
                        print!("\u{8} \u{8}");
                    }
                }
                code if code >= 0x20 && pin.len() < MAX_PIN_CHARS => {
                    pin.push(code);
                    print!("*");
                }
                _ => {}
            },
            Key::Special(_) => {}
        }
    }

    Ok(pin)
}

/// Return true if the just-read ESC should abort. ESC followed by another ESC
/// also aborts. ESC followed by anything else is treated as a terminal escape
/// sequence, drained, and ignored.
fn escape_aborts() -> Outcome<bool> {
    let Some(key) = input::read_key()? else {
        return Ok(true);
    };
    if input::is_escape_key(key) {
        return Ok(true);
    }

    input::drain_pending_keys()?;
    Ok(false)
}

fn abort_from_prompt() -> ! {
    println!();
    info!("aborted, rebooting...");
    runtime::reset(runtime::ResetType::WARM, Status::SUCCESS, None);
}

/// Build `"pinnacle" || pcr_index_le || argon2id(pin)` and extend it into the
/// PIN PCR. The TPM must already be open and validated (see `open_tpm`).
fn extend_pin_to_pcr(tcg: &mut Tcg, salt: &[u8], pin: &[u16]) -> Outcome {
    info!("deriving measurement...");
    let derived = derive_pin_hash(salt, pin)?;

    let mut data = Scrubbed::new(Vec::with_capacity(
        DOMAIN_PREFIX.len() + core::mem::size_of::<u32>() + PIN_HASH_LEN,
    ));
    data.extend_from_slice(DOMAIN_PREFIX);
    data.extend_from_slice(&PIN_PCR_INDEX.to_le_bytes());
    data.extend_from_slice(&derived);

    let event =
        PcrEventInputs::new_in_box(PcrIndex(PIN_PCR_INDEX), EventType::EFI_ACTION, EVENT_TEXT)?;

    // EFI_TCG2_EXTEND_ONLY suppresses the event-log entry; the PCR is extended
    // either way. `debug-event-log` records it for `tpm2_eventlog`.
    let flags = if cfg!(feature = "debug-event-log") {
        HashLogExtendEventFlags::empty()
    } else {
        HashLogExtendEventFlags::EFI_TCG2_EXTEND_ONLY
    };

    tcg.hash_log_extend_event(flags, &data, &event)?;
    info!("extended PIN-derived measurement to PCR[{}]", PIN_PCR_INDEX);
    pcr::debug(tcg);
    Ok(())
}

/// Derive a memory-hard hash of the PIN with Argon2id. The password input is
/// the little-endian serialization of the UEFI CHAR16 code units. Both the
/// serialized PIN and the derived hash live in scrubbed buffers.
fn derive_pin_hash(salt: &[u8], pin: &[u16]) -> Outcome<Scrubbed<u8>> {
    // Each CHAR16/u16 code unit serializes to two bytes, exact preallocation
    // avoids reallocation after secret bytes have been written.
    let mut pin_bytes = Scrubbed::new(Vec::with_capacity(pin.len() * 2));
    for unit in pin {
        pin_bytes.extend_from_slice(&unit.to_le_bytes());
    }

    let params = Params::new(
        ARGON2_MEM_KIB,
        ARGON2_TIME,
        ARGON2_LANES,
        Some(PIN_HASH_LEN),
    )
    .map_err(|_| Status::INVALID_PARAMETER)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Allocate and size the output before Argon2 writes the secret bytes, so no
    // later resize can move them to a new allocation.
    let mut derived = Scrubbed::new(Vec::with_capacity(PIN_HASH_LEN));
    derived.resize(PIN_HASH_LEN, 0);
    argon2
        .hash_password_into(&pin_bytes, salt, derived.as_mut_slice())
        .map_err(|_| Status::OUT_OF_RESOURCES)?;

    Ok(derived)
}

/// The Argon2id salt for this machine: the SMBIOS system UUID when present,
/// else `FALLBACK_SALT` (see the README).
fn pin_salt(uuid: Option<&[u8; 16]>) -> &[u8] {
    match uuid {
        Some(u) => debug!("SMBIOS system UUID: {}", Hex(u)),
        None => error!("SMBIOS system UUID: <read failed>"),
    }

    // Judge whether the UUID value is usable or if we should use the fallback.
    match uuid {
        None => {
            warn!("SMBIOS system UUID not found, using fallback salt");
            FALLBACK_SALT
        }
        Some(u) if u.iter().all(|&b| b == 0) || u.iter().all(|&b| b == 0xff) => {
            warn!("SMBIOS system UUID is trivial, using fallback salt");
            FALLBACK_SALT
        }
        Some(u) => u,
    }
}

/// Read the SMBIOS system UUID (Type 1 structure, 16 bytes at offset 0x08).
/// Returns `None` only when the SMBIOS tables or the Type 1 structure are
/// absent/corrupt for reason.
fn read_smbios_uuid() -> Option<[u8; 16]> {
    let (addr, size) = locate_smbios()?;
    if addr == 0 || size == 0 {
        return None;
    }

    let data = unsafe { core::slice::from_raw_parts(addr as *const u8, size) };
    let mut off = 0;
    while off + 4 <= data.len() {
        let ty = data[off];
        let len = data[off + 1] as usize;
        if len < 4 || off + len > data.len() {
            break;
        }
        if ty == 0x7f {
            break; // end-of-table marker
        }
        if ty == 1 && len >= 0x18 {
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&data[off + 0x08..off + 0x18]);
            return Some(uuid);
        }
        // Skip the formatted area and the string-set (terminated by a double NUL).
        let mut end = off + len;
        while end + 1 < data.len() && !(data[end] == 0 && data[end + 1] == 0) {
            end += 1;
        }
        off = end + 2;
    }

    None
}

/// Locate the SMBIOS structure table `(address, size)` from the UEFI config
/// table, preferring the 64-bit (SMBIOS 3) entry point over the 32-bit one.
fn locate_smbios() -> Option<(usize, usize)> {
    system::with_config_table(|entries| {
        if let Some(e) = entries
            .iter()
            .find(|e| e.guid == ConfigTableEntry::SMBIOS3_GUID)
        {
            let ep = e.address as *const u8;
            let size = unsafe { core::ptr::read_unaligned(ep.add(0x0c).cast::<u32>()) } as usize;
            let addr = unsafe { core::ptr::read_unaligned(ep.add(0x10).cast::<u64>()) } as usize;
            Some((addr, size))
        } else if let Some(e) = entries
            .iter()
            .find(|e| e.guid == ConfigTableEntry::SMBIOS_GUID)
        {
            let ep = e.address as *const u8;
            let size = unsafe { core::ptr::read_unaligned(ep.add(0x16).cast::<u16>()) } as usize;
            let addr = unsafe { core::ptr::read_unaligned(ep.add(0x18).cast::<u32>()) } as usize;
            Some((addr, size))
        } else {
            None
        }
    })
}

/// Locate `NEXT_LOADER_PATH` across all filesystem volumes and load it
/// (running the Secure Boot check for it), returning the ready-to-start image.
/// pinnacle's own volume is tried last.
fn load_next() -> Outcome<Handle> {
    let image = boot::image_handle();
    let own = boot::open_protocol_exclusive::<LoadedImage>(image)?.device();

    info!("searching for {}...", NEXT_LOADER_PATH);
    let mut volumes = boot::find_handles::<SimpleFileSystem>()?;
    volumes.sort_by_key(|handle| Some(*handle) == own);

    for volume in volumes {
        let loader_path = loader_path_on_volume(volume);
        match load_from_volume(volume, image) {
            Ok(next) => {
                info!("loaded {loader_path}");
                return Ok(next);
            }
            Err(error) if error.status() == Status::NOT_FOUND => {} // not found, next
            Err(error) => {
                error!("{loader_path} load failed: {error}");
            }
        }
    }

    fatal!(
        Status::NOT_FOUND,
        "no usable {NEXT_LOADER_PATH} found, is the boot loader installed and signed?"
    )
}

/// Best-effort printable full path of `NEXT_LOADER_PATH` on `volume`.
fn loader_path_on_volume(volume: Handle) -> String {
    match boot::open_protocol_exclusive::<DevicePath>(volume) {
        Ok(device_path) => format!("{device_path}{NEXT_LOADER_PATH}"),
        Err(_) => format!("{volume:?}{NEXT_LOADER_PATH}"),
    }
}

/// Load `NEXT_LOADER_PATH` from a single filesystem volume.
fn load_from_volume(volume: Handle, parent: Handle) -> uefi::Result<Handle> {
    let device_path = boot::open_protocol_exclusive::<DevicePath>(volume)?;

    let mut buf = Vec::new();
    let mut builder = DevicePathBuilder::with_vec(&mut buf);
    for node in device_path.node_iter() {
        builder = builder.push(&node).map_err(|_| Status::OUT_OF_RESOURCES)?;
    }
    let full_path = builder
        .push(&FilePath {
            path_name: NEXT_LOADER_PATH,
        })
        .and_then(DevicePathBuilder::finalize)
        .map_err(|_| Status::OUT_OF_RESOURCES)?;

    boot::load_image(
        parent,
        boot::LoadImageSource::FromDevicePath {
            device_path: full_path,
            boot_policy: BootPolicy::ExactMatch,
        },
    )
}
