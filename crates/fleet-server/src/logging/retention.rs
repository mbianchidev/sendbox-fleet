//! Deletes inactive log files older than the retention window.
//!
//! Only regular files named `sendbox-fleet.YYYY-MM-DD.log` directly inside the
//! log directory are candidates; symlinks, directories, and every other file
//! are left untouched. A file's age comes from the UTC date in its name, not
//! its modification time, so copying or touching a file does not extend its
//! retention. A file is deleted when its last possible record (the end of its
//! UTC day) is at or before `now - retention`; the current day's live file is
//! therefore never eligible.

use std::io;
use std::ops::Range;
use std::path::{Path, PathBuf};

use time::{Date, Duration, Month, OffsetDateTime};

use super::{LOG_FILE_PREFIX, LOG_FILE_SUFFIX};

#[derive(Debug, Default)]
pub struct RetentionReport {
    pub deleted: Vec<PathBuf>,
    pub failures: Vec<(PathBuf, io::Error)>,
}

/// Applies retention once. Fails only when the directory cannot be listed;
/// individual deletion failures are collected and the remaining eligible files
/// are still processed.
pub fn enforce(
    dir: &Path,
    retention_days: u32,
    now: OffsetDateTime,
) -> io::Result<RetentionReport> {
    let cutoff = now - Duration::days(i64::from(retention_days));
    let mut report = RetentionReport::default();
    for entry in std::fs::read_dir(dir)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                report.failures.push((dir.to_path_buf(), error));
                continue;
            }
        };
        let Some(day) = entry.file_name().to_str().and_then(log_file_day) else {
            continue;
        };
        let Some(end_of_day) = day.next_day().map(|next| next.midnight().assume_utc()) else {
            continue;
        };
        if end_of_day > cutoff {
            continue;
        }
        let path = entry.path();
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => match std::fs::remove_file(&path) {
                Ok(()) => report.deleted.push(path),
                Err(error) => report.failures.push((path, error)),
            },
            Ok(_) => {}
            Err(error) => report.failures.push((path, error)),
        }
    }
    Ok(report)
}

/// The UTC day encoded in a file name produced by the daily appender.
fn log_file_day(name: &str) -> Option<Date> {
    let date = name
        .strip_prefix(LOG_FILE_PREFIX)?
        .strip_prefix('.')?
        .strip_suffix(LOG_FILE_SUFFIX)?
        .strip_suffix('.')?;
    let bytes = date.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let number = |range: Range<usize>| -> Option<u16> {
        let digits = date.get(range)?;
        if digits.bytes().all(|byte| byte.is_ascii_digit()) {
            digits.parse().ok()
        } else {
            None
        }
    };
    let year = i32::from(number(0..4)?);
    let month = Month::try_from(u8::try_from(number(5..7)?).ok()?).ok()?;
    let day = u8::try_from(number(8..10)?).ok()?;
    Date::from_calendar_date(year, month, day).ok()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use time::macros::datetime;

    use super::*;

    fn touch(dir: &Path, name: &str) {
        fs::write(dir.join(name), b"{\"message\":\"synthetic\"}\n").unwrap();
    }

    fn deleted_names(report: &RetentionReport) -> Vec<String> {
        let mut names: Vec<String> = report
            .deleted
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn deletes_only_files_whose_day_ended_by_the_cutoff() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "sendbox-fleet.2026-09-01.log",
            "sendbox-fleet.2026-10-15.log",
            "sendbox-fleet.2026-10-16.log",
            "sendbox-fleet.2026-11-15.log",
        ] {
            touch(dir.path(), name);
        }
        let report = enforce(dir.path(), 30, datetime!(2026-11-15 00:00 UTC)).unwrap();
        assert_eq!(
            deleted_names(&report),
            [
                "sendbox-fleet.2026-09-01.log",
                "sendbox-fleet.2026-10-15.log"
            ]
        );
        assert!(report.failures.is_empty());

        let report = enforce(dir.path(), 30, datetime!(2026-11-15 23:59:59 UTC)).unwrap();
        assert!(report.deleted.is_empty());

        let report = enforce(dir.path(), 30, datetime!(2026-11-16 00:00 UTC)).unwrap();
        assert_eq!(deleted_names(&report), ["sendbox-fleet.2026-10-16.log"]);
        assert!(dir.path().join("sendbox-fleet.2026-11-15.log").exists());
    }

    #[test]
    fn leaves_unrecognized_entries_and_symlink_targets_alone() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        touch(outside.path(), "sendbox-fleet.2020-01-01.log");
        let target = outside.path().join("sendbox-fleet.2020-01-01.log");
        let keep = [
            "other-app.2020-01-01.log",
            "sendbox-fleet.2020-01-01.txt",
            "sendbox-fleet.2020-13-01.log",
            "sendbox-fleet.2020-1-01.log",
            "sendbox-fleet.log",
        ];
        for name in keep {
            touch(dir.path(), name);
        }
        fs::create_dir(dir.path().join("sendbox-fleet.2020-01-02.log")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, dir.path().join("sendbox-fleet.2020-01-03.log"))
            .unwrap();

        let report = enforce(dir.path(), 1, datetime!(2026-11-15 12:00 UTC)).unwrap();
        assert!(report.deleted.is_empty(), "{:?}", report.deleted);
        assert!(report.failures.is_empty());
        assert!(target.exists());
        for name in keep {
            assert!(dir.path().join(name).exists(), "{name} was removed");
        }
        assert!(dir.path().join("sendbox-fleet.2020-01-02.log").is_dir());
    }

    #[test]
    fn unreadable_directory_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(enforce(&dir.path().join("absent"), 30, OffsetDateTime::now_utc()).is_err());
    }
}
