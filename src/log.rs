// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Minimal leveled logger for the UEFI environment. Each line carries a
//! wall-clock timestamp (read from the platform RTC) and a log level. It is
//! `no_std` and lightweight: it writes to the UEFI stdout console directly.
//!
//! Use the `error!`, `warn!`, `info!`, and `debug!` macros. They format like
//! `println!` and prepend an RFC 3339 timestamp and a color-coded level. Lines
//! more verbose than [`LEVEL`] are dropped.

use alloc::string::String;
use core::fmt::{self, Display, Formatter, Write as _};

use uefi::proto::console::text::Color;
use uefi::{runtime, system, Status};

use crate::input;

/// Global log level, `Debug` by default
pub const LEVEL: Level = Level::Debug;

macro_rules! error {
    ($($arg:tt)*) => { $crate::log::emit($crate::log::Level::Error, format_args!($($arg)*)) };
}
macro_rules! warn {
    ($($arg:tt)*) => { $crate::log::emit($crate::log::Level::Warn, format_args!($($arg)*)) };
}
macro_rules! info {
    ($($arg:tt)*) => { $crate::log::emit($crate::log::Level::Info, format_args!($($arg)*)) };
}
macro_rules! debug {
    ($($arg:tt)*) => { $crate::log::emit($crate::log::Level::Debug, format_args!($($arg)*)) };
}
// Info-level header and message with no trailing newline, for an inline prompt.
macro_rules! prompt {
    ($($arg:tt)*) => { $crate::log::prompt(format_args!($($arg)*)) };
}
// Returns `Err(Fatal)` from the enclosing function, built from a status and a
// `format!`-style message (like `anyhow::bail!`).
macro_rules! fatal {
    ($status:expr, $($arg:tt)*) => {
        return Err($crate::log::Fatal::new($status, alloc::format!($($arg)*)))
    };
}

/// LightGray on Black is the conventional UEFI text-console default (there is
/// no API to read the current color back, so we default/restore to this).
const DEFAULT_FG: Color = Color::LightGray;
const DEFAULT_BG: Color = Color::Black;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Fatal,
    Error,
    Warn,
    Info,
    Debug,
}

impl Level {
    const fn label(self) -> &'static str {
        match self {
            Level::Fatal => "FTL",
            Level::Error => "ERR",
            Level::Warn => "WRN",
            Level::Info => "INF",
            Level::Debug => "DBG",
        }
    }

    const fn color(self) -> Color {
        match self {
            Level::Fatal => Color::Red,
            Level::Error => Color::LightRed,
            Level::Warn => Color::Yellow,
            Level::Info => Color::LightGreen,
            Level::Debug => Color::DarkGray,
        }
    }
}

/// Check if the given log level is enabled
pub fn enabled(level: Level) -> bool {
    level <= LEVEL
}

/// RFC 3339 numeric offset for an optional UEFI timezone (minutes east of UTC,
/// as `Time::time_zone` reports). `None`, the EFI "unspecified timezone",
/// i.e. local time with unknown offset, renders as `-00:00` per RFC 3339's
/// unknown-local-offset convention. A zero offset renders as `Z`.
struct Rfc3339Offset(Option<i16>);

impl Display for Rfc3339Offset {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            None => f.write_str("-00:00"),
            Some(0) => f.write_str("Z"),
            Some(min) => {
                let sign = if min < 0 { '-' } else { '+' };
                let min = min.unsigned_abs();
                write!(f, "{sign}{:02}:{:02}", min / 60, min % 60)
            }
        }
    }
}

/// Lowercase-hex `Display` adapter for a byte slice, for logging digests, UUIDs
/// and the like.
pub(crate) struct Hex<'a>(pub &'a [u8]);

impl Display for Hex<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Emit one formatted log line with an RFC 3339 timestamp and a color-coded
/// level. Called by the logging macros, not meant to be used directly.
pub fn emit(level: Level, args: core::fmt::Arguments) {
    if !enabled(level) {
        return;
    }

    line(level, args, true);
}

/// Emit an info-level header and message with no trailing newline, so the caller
/// can read input on the same line (used for the PIN prompt).
pub fn prompt(args: core::fmt::Arguments) {
    line(Level::Info, args, false);
}

fn line(level: Level, args: core::fmt::Arguments, newline: bool) {
    let time = runtime::get_time().ok();

    // Write the whole line under one stdout lock so the color changes wrap only
    // the label. Console/formatting errors are ignored; logging must not fail
    // the boot.
    system::with_stdout(|out| {
        let _ = out.set_color(DEFAULT_FG, DEFAULT_BG);
        let _ = match time {
            Some(t) => write!(
                out,
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{} [",
                t.year(),
                t.month(),
                t.day(),
                t.hour(),
                t.minute(),
                t.second(),
                Rfc3339Offset(t.time_zone()),
            ),
            None => write!(out, "----------T--:--:--Z ["),
        };
        let _ = out.set_color(level.color(), DEFAULT_BG);
        let _ = write!(out, "{}", level.label());
        let _ = out.set_color(DEFAULT_FG, DEFAULT_BG);
        if newline {
            let _ = writeln!(out, "] {args}");
        } else {
            let _ = write!(out, "] {args}");
        }
    });
}

/// A fatal error: a UEFI status plus an operator-facing message. Propagated
/// up to `main`, which reports it through `report()`.
pub struct Fatal {
    status: Status,
    message: String,
}

impl Fatal {
    pub fn new(status: Status, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    /// Print the message at fatal level, pause for a keypress so it stays on
    /// screen, then reboot (in a warm way, with automatic fallback to cold).
    pub fn report(self) -> ! {
        emit(Level::Fatal, format_args!("{}", self.message));
        input::wait_for_key();
        runtime::reset(runtime::ResetType::WARM, self.status, None)
    }
}

// Let `?` turn incidental UEFI errors into fatals carrying their status, so an
// unexpected failure is reported rather than exiting blank.
impl From<Status> for Fatal {
    fn from(status: Status) -> Self {
        Self::new(status, alloc::format!("unexpected error: {status}"))
    }
}

impl From<uefi::Error> for Fatal {
    fn from(error: uefi::Error) -> Self {
        error.status().into()
    }
}

/// Result whose error carries a status and an operator-facing message, returned
/// by the fallible boot steps and reported by `main`.
pub type Outcome<T = ()> = core::result::Result<T, Fatal>;
