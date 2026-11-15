//! Log file writer that rotates at each UTC day and when a file reaches a
//! size limit.
//!
//! The first file of a day is `sendbox-fleet.YYYY-MM-DD.log`; when it reaches
//! the limit, writing continues in `sendbox-fleet.YYYY-MM-DD.1.log`, `.2.log`,
//! and so on. Files are created with mode `0600`. A single background thread
//! owns the writer, so no locking is needed.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use time::{Date, OffsetDateTime};

use super::{LOG_FILE_PREFIX, LOG_FILE_SUFFIX};

/// Highest part number tried for one day before writing to the last one.
const MAX_PARTS: u32 = 9_999;

pub type Today = Box<dyn Fn() -> Date + Send>;

struct Current {
    day: Date,
    part: u32,
    file: File,
    size: u64,
}

pub struct RotatingFile {
    dir: PathBuf,
    max_bytes: u64,
    today: Today,
    current: Option<Current>,
}

/// The file name of one part of a day's log.
#[must_use]
pub fn file_name(day: Date, part: u32) -> String {
    if part == 0 {
        format!("{LOG_FILE_PREFIX}.{day}.{LOG_FILE_SUFFIX}")
    } else {
        format!("{LOG_FILE_PREFIX}.{day}.{part}.{LOG_FILE_SUFFIX}")
    }
}

impl RotatingFile {
    pub fn new(dir: &Path, max_bytes: u64) -> io::Result<Self> {
        Self::with_clock(
            dir,
            max_bytes,
            Box::new(|| OffsetDateTime::now_utc().date()),
        )
    }

    pub fn with_clock(dir: &Path, max_bytes: u64, today: Today) -> io::Result<Self> {
        let mut writer = Self {
            dir: dir.to_path_buf(),
            max_bytes: max_bytes.max(1),
            today,
            current: None,
        };
        writer.ensure(0)?;
        Ok(writer)
    }

    fn open(&self, day: Date, part: u32) -> io::Result<Current> {
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(self.dir.join(file_name(day, part)))?;
        let size = file.metadata()?.len();
        Ok(Current {
            day,
            part,
            file,
            size,
        })
    }

    /// Makes sure the current file is today's and has room for `incoming`
    /// bytes, starting a new part when it is full.
    fn ensure(&mut self, incoming: u64) -> io::Result<()> {
        let day = (self.today)();
        let mut part = match &self.current {
            Some(current) if current.day == day => {
                if current.size == 0 || current.size + incoming <= self.max_bytes {
                    return Ok(());
                }
                current.part + 1
            }
            _ => 0,
        };
        loop {
            let opened = self.open(day, part)?;
            if opened.size == 0 || opened.size + incoming <= self.max_bytes || part >= MAX_PARTS {
                if let Some(previous) = self.current.as_mut() {
                    previous.file.flush()?;
                }
                self.current = Some(opened);
                return Ok(());
            }
            part += 1;
        }
    }
}

impl Write for RotatingFile {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.ensure(buffer.len() as u64)?;
        let current = self
            .current
            .as_mut()
            .ok_or_else(|| io::Error::other("no log file is open"))?;
        let written = current.file.write(buffer)?;
        current.size += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.current.as_mut() {
            Some(current) => current.file.flush(),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU8, Ordering};

    use time::macros::date;

    use super::*;

    #[test]
    fn rotates_by_size_within_a_day_and_at_each_day() {
        let dir = tempfile::tempdir().unwrap();
        let day = Arc::new(AtomicU8::new(15));
        let clock = Arc::clone(&day);
        let mut writer = RotatingFile::with_clock(
            dir.path(),
            10,
            Box::new(move || {
                date!(2026 - 11 - 01)
                    .replace_day(clock.load(Ordering::SeqCst))
                    .unwrap()
            }),
        )
        .unwrap();
        for line in ["12345678\n", "abcdefgh\n", "ABCDEFGH\n"] {
            writer.write_all(line.as_bytes()).unwrap();
        }
        day.store(16, Ordering::SeqCst);
        writer.write_all(b"next day\n").unwrap();
        writer.flush().unwrap();
        let read = |name: &str| std::fs::read_to_string(dir.path().join(name)).unwrap();
        assert_eq!(read("sendbox-fleet.2026-11-15.log"), "12345678\n");
        assert_eq!(read("sendbox-fleet.2026-11-15.1.log"), "abcdefgh\n");
        assert_eq!(read("sendbox-fleet.2026-11-15.2.log"), "ABCDEFGH\n");
        assert_eq!(read("sendbox-fleet.2026-11-16.log"), "next day\n");

        drop(writer);
        day.store(15, Ordering::SeqCst);
        let mut reopened =
            RotatingFile::with_clock(dir.path(), 10, Box::new(|| date!(2026 - 11 - 15))).unwrap();
        reopened.write_all(b"restart\n").unwrap();
        reopened.flush().unwrap();
        assert_eq!(read("sendbox-fleet.2026-11-15.3.log"), "restart\n");
    }
}
