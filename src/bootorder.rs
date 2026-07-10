// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Register pinnacle as the first UEFI boot option so the PIN gate is the
//! default on every subsequent boot. Best-effort: NVRAM-variable failures are
//! logged and never abort the boot.

use alloc::boxed::Box;
use alloc::vec::Vec;

use uefi::proto::device_path::DevicePath;
use uefi::runtime::{VariableAttributes, VariableVendor};
use uefi::{boot, cstr16, runtime, CStr16, CString16, Status};

/// Boot-entry description shown in the firmware menu, kept ASCII so it widens
/// cleanly to the UCS-2 `DESCRIPTION_BYTES` below.
const DESCRIPTION: &str = "pinnacle";

/// `DESCRIPTION` as stored in an `EFI_LOAD_OPTION`: little-endian UCS-2 with a
/// NUL terminator, materialized once at compile time. Also the marker that
/// recognizes pinnacle's own entries across reboots (see `is_ours`).
static DESCRIPTION_BYTES: [u8; (DESCRIPTION.len() + 1) * 2] = {
    let src = DESCRIPTION.as_bytes();
    let mut out = [0u8; (DESCRIPTION.len() + 1) * 2];
    let mut i = 0;
    while i < src.len() {
        assert!(src[i] < 0x80, "DESCRIPTION must be ASCII");
        out[2 * i] = src[i];
        i += 1;
    }
    out
};

/// The `BootOrder` global variable: a little-endian array of `Boot####` indices.
const BOOT_ORDER: &CStr16 = cstr16!("BootOrder");

/// `LOAD_OPTION_ACTIVE`: the entry is a valid boot candidate.
const LOAD_OPTION_ACTIVE: u32 = 0x0000_0001;

/// Non-volatile so the entry persists, with both access flags as the UEFI spec
/// requires for the `Boot####`/`BootOrder` variables.
const ATTRS: VariableAttributes = VariableAttributes::NON_VOLATILE
    .union(VariableAttributes::BOOTSERVICE_ACCESS)
    .union(VariableAttributes::RUNTIME_ACCESS);

/// Ensure a `Boot####` entry for this image exists and is first in `BootOrder`.
/// Any failure is logged but does not stop pinnacle.
pub fn ensure_first() {
    if let Err(status) = install() {
        warn!("could not make pinnacle the first boot option: {status}");
    }
}

fn install() -> uefi::Result {
    let desired = build_option(&own_boot_path()?);
    let Scan { mut ours, used } = scan();
    let mut changed = false;

    // Keep one entry, preferring one that already matches to avoid a write, and
    // leave every other pinnacle entry in `ours` as a stale duplicate to purge.
    let number = match ours.iter().position(|entry| entry.option == desired) {
        Some(index) => ours.swap_remove(index).number,
        None => {
            let number = match ours.pop() {
                Some(entry) => entry.number,
                None => first_free(&used).ok_or(Status::OUT_OF_RESOURCES)?,
            };
            write_entry(number, &desired)?;
            changed = true;
            number
        }
    };

    // Purge leftover duplicates (e.g. from an install-time removable device) so
    // the boot menu does not accumulate stale pinnacle entries.
    for entry in &ours {
        delete_entry(entry.number)?;
        changed = true;
    }

    // Our entry first, with the purged duplicates (still in `ours`) dropped.
    let order = read_boot_order();
    let mut next = Vec::with_capacity(order.len() + 1);
    next.push(number);
    next.extend(
        order
            .iter()
            .copied()
            .filter(|n| *n != number && ours.iter().all(|entry| entry.number != *n)),
    );
    if next != order {
        write_boot_order(&next)?;
        changed = true;
    }

    if changed {
        info!("set pinnacle as the first boot option (Boot{number:04X})");
    } else {
        debug!("pinnacle is already the first boot option (Boot{number:04X})");
    }
    Ok(())
}

/// The full device path that boots this image: the device it was loaded from
/// followed by the file path within that device.
fn own_boot_path() -> uefi::Result<Box<DevicePath>> {
    crate::with_own_image(|loaded| {
        let device = loaded.device().ok_or(Status::NOT_FOUND)?;
        let file = loaded.file_path().ok_or(Status::NOT_FOUND)?;
        let device_path = boot::open_protocol_exclusive::<DevicePath>(device)?;
        crate::join_device_path(&device_path, file)
    })?
}

/// Serialize an `EFI_LOAD_OPTION` for `path` with our description and no
/// optional data.
fn build_option(path: &DevicePath) -> Vec<u8> {
    let path = path.as_bytes();
    let mut option = Vec::new();
    option.extend_from_slice(&LOAD_OPTION_ACTIVE.to_le_bytes());
    option.extend_from_slice(&(path.len() as u16).to_le_bytes());
    option.extend_from_slice(&DESCRIPTION_BYTES);
    option.extend_from_slice(path);
    option
}

/// A `Boot####` entry: its index and the raw `EFI_LOAD_OPTION` bytes.
struct Entry {
    number: u16,
    option: Vec<u8>,
}

/// Outcome of scanning the global boot entries.
struct Scan {
    /// Entries pinnacle created, matched by description.
    ours: Vec<Entry>,
    /// Every `Boot####` index currently in use.
    used: Vec<u16>,
}

/// Scan the global `Boot####` variables for pinnacle's own entries and the set
/// of indices already in use.
fn scan() -> Scan {
    let mut ours = Vec::new();
    let mut used = Vec::new();

    for key in runtime::variable_keys() {
        let Ok(key) = key else { continue };
        if key.vendor != VariableVendor::GLOBAL_VARIABLE {
            continue;
        }
        let Some(number) = entry_number(&key.name) else {
            continue;
        };
        used.push(number);

        if let Ok((bytes, _)) = runtime::get_variable_boxed(&key.name, &key.vendor) {
            if is_ours(&bytes) {
                ours.push(Entry {
                    number,
                    option: bytes.into_vec(),
                });
            }
        }
    }

    Scan { ours, used }
}

/// Whether a serialized `EFI_LOAD_OPTION` carries our exact description, i.e.,
/// is an entry pinnacle created.
fn is_ours(option: &[u8]) -> bool {
    // The Description follows the u32 Attributes and u16 FilePathListLength.
    option.get(6..6 + DESCRIPTION_BYTES.len()) == Some(DESCRIPTION_BYTES.as_slice())
}

/// Parse `Boot####` (four hex digits) into its index, rejecting other names.
fn entry_number(name: &CStr16) -> Option<u16> {
    let chars = name.as_slice();
    if chars.len() != 8 || !chars.iter().zip("Boot".chars()).all(|(c, p)| *c == p) {
        return None;
    }
    let mut value = 0u16;
    for c in &chars[4..] {
        value = value << 4 | char::from(*c).to_digit(16)? as u16;
    }
    Some(value)
}

/// Lowest `Boot####` index not already present.
fn first_free(used: &[u16]) -> Option<u16> {
    (0..=u16::MAX).find(|n| !used.contains(n))
}

/// The `Boot####` variable name for an index. The formatted string is pure
/// ASCII, so the conversion cannot fail.
fn entry_name(number: u16) -> CString16 {
    CString16::try_from(alloc::format!("Boot{number:04X}").as_str()).unwrap()
}

fn read_boot_order() -> Vec<u16> {
    match runtime::get_variable_boxed(BOOT_ORDER, &VariableVendor::GLOBAL_VARIABLE) {
        Ok((data, _)) => data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn write_boot_order(order: &[u16]) -> uefi::Result {
    let bytes: Vec<u8> = order.iter().flat_map(|n| n.to_le_bytes()).collect();
    runtime::set_variable(BOOT_ORDER, &VariableVendor::GLOBAL_VARIABLE, ATTRS, &bytes)
}

fn write_entry(number: u16, option: &[u8]) -> uefi::Result {
    runtime::set_variable(
        &entry_name(number),
        &VariableVendor::GLOBAL_VARIABLE,
        ATTRS,
        option,
    )
}

fn delete_entry(number: u16) -> uefi::Result {
    runtime::delete_variable(&entry_name(number), &VariableVendor::GLOBAL_VARIABLE)
}
