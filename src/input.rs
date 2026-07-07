// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Console input helpers shared by the PIN prompt and fatal-error pause.

use uefi::proto::console::text::{Key, ScanCode};
use uefi::{boot, system, Result};

pub fn read_key() -> Result<Option<Key>> {
    system::with_stdin(|stdin| stdin.read_key())
}

pub fn drain_pending_keys() -> Result<()> {
    while read_key()?.is_some() {}
    Ok(())
}

pub fn is_escape_key(key: Key) -> bool {
    match key {
        Key::Special(code) => code == ScanCode::ESCAPE,
        Key::Printable(c) => u16::from(c) == 0x1b,
    }
}

/// Block until the user presses a key. Best effort: if console input fails,
/// return so fatal-error reporting can continue to reset the machine.
pub fn wait_for_key() {
    // Flush buffered keystrokes so stray earlier presses do not skip the pause.
    let _ = drain_pending_keys();

    let Ok(event) = system::with_stdin(|stdin| stdin.wait_for_key_event()) else {
        return;
    };
    let mut events = [event];
    loop {
        if boot::wait_for_event(&mut events).is_err() {
            return;
        }
        match read_key() {
            Ok(Some(_)) => return,
            Ok(None) => continue, // spurious wake, keep waiting
            Err(_) => return,
        }
    }
}
