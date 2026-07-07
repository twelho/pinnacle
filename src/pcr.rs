// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Reading TPM PCR values. Used to assert the PIN PCR is clean before extending
//! and to debug-print it. The TCG2 protocol has no read-PCR call, so this issues
//! a raw `TPM2_PCR_Read` via `submit_command`.

use uefi::proto::tcg::v2::Tcg;
use uefi::Status;

use crate::log::{self, Hex, Level, Outcome};
use crate::PIN_PCR_INDEX;

/// Fail unless the PIN PCR reads all-zero, used to abort on boot loops and
/// other interjections.
pub fn assert_clean(tcg: &mut Tcg) -> Outcome {
    let Some(value) = read_sha256(tcg, PIN_PCR_INDEX) else {
        fatal!(
            Status::DEVICE_ERROR,
            "could not read PCR[{}], the TPM may be faulty",
            PIN_PCR_INDEX
        );
    };
    debug!("PCR[{}]: {}", PIN_PCR_INDEX, Hex(&value));
    if value.iter().any(|&b| b != 0) {
        fatal!(
            Status::SECURITY_VIOLATION,
            "PCR[{}] already extended, did a boot loop re-enter pinnacle?",
            PIN_PCR_INDEX
        );
    }
    Ok(())
}

/// Debug-print the SHA-256 value of the PIN PCR. Gated on the debug level so the
/// extra TPM round-trip is skipped entirely when debug logging is off.
pub fn debug(tcg: &mut Tcg) {
    if !log::enabled(Level::Debug) {
        return;
    }

    match read_sha256(tcg, PIN_PCR_INDEX) {
        Some(v) => debug!("PCR[{}]: {}", PIN_PCR_INDEX, Hex(&v)),
        None => error!("PCR[{}]: <read failed>", PIN_PCR_INDEX),
    }
}

/// Read the SHA-256 bank value of a PCR via a raw `TPM2_PCR_Read` command.
/// Returns `None` on any protocol or parse error. TPM wire format is big-endian.
fn read_sha256(tcg: &mut Tcg, index: u32) -> Option<[u8; 32]> {
    // Single-PCR selection in the SHA-256 bank: pcrSelect is a little bitmap
    // where PCR n is bit (n % 8) of byte (n / 8).
    let mut select = [0u8; 3];
    *select.get_mut((index / 8) as usize)? = 1 << (index % 8);

    #[rustfmt::skip]
    let cmd: [u8; 20] = [
        0x80, 0x01,             // tag: TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x14, // commandSize = 20
        0x00, 0x00, 0x01, 0x7e, // commandCode: TPM_CC_PCR_Read
        0x00, 0x00, 0x00, 0x01, // pcrSelectionIn.count = 1
        0x00, 0x0b,             // hash: TPM_ALG_SHA256
        0x03,                   // sizeofSelect = 3
        select[0], select[1], select[2],
    ];

    let mut resp = [0u8; 128];
    tcg.submit_command(&cmd, &mut resp).ok()?;

    // Response: tag(2) size(4) responseCode(4) pcrUpdateCounter(4)
    //   pcrSelectionOut: count(4) then [hash(2) sizeofSelect(1) select(n)]...
    //   pcrValues: count(4) then [size(2) digest(size)]...
    let code = u32::from_be_bytes(resp.get(6..10)?.try_into().ok()?);
    if code != 0 {
        return None;
    }
    let mut off = 14; // skip 10-byte header + 4-byte pcrUpdateCounter
    let selections = u32::from_be_bytes(resp.get(off..off + 4)?.try_into().ok()?);
    off += 4;
    for _ in 0..selections {
        let size_of_select = *resp.get(off + 2)? as usize;
        off += 3 + size_of_select;
    }
    let digests = u32::from_be_bytes(resp.get(off..off + 4)?.try_into().ok()?);
    off += 4;
    let size = u16::from_be_bytes(resp.get(off..off + 2)?.try_into().ok()?) as usize;
    off += 2;
    if digests < 1 || size != 32 {
        return None;
    }
    resp.get(off..off + 32)?.try_into().ok()
}
