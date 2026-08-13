//! RFC 3339 timestamps in the format required by the Ark spec:
//! millisecond precision, `Z`-terminated (e.g. `2026-07-28T13:45:07.123Z`).

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use time::format_description::FormatItem;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::OffsetDateTime;

const OUTPUT_FORMAT: &[FormatItem<'static>] = format_description!(
    "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
);

/// Current UTC wall-clock time, truncated to millisecond precision to match
/// what the wire format can represent.
pub fn now() -> OffsetDateTime {
    truncate_to_millis(OffsetDateTime::now_utc())
}

/// Current wall-clock time as milliseconds since the Unix epoch. Used by
/// authentication timestamps and any other places that need a compact
/// integer clock value.
pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// Format a timestamp in the spec's canonical form (millisecond precision,
/// `Z`-terminated). The input is truncated to milliseconds first.
pub fn format(dt: OffsetDateTime) -> String {
    truncate_to_millis(dt).format(&OUTPUT_FORMAT).expect("format rfc3339")
}

/// Same as [`format`] but with `:` replaced by `-` so the result is safe to
/// use as a filename component on filesystems that reject colons.
pub fn format_fs_safe(dt: OffsetDateTime) -> String {
    format(dt).replace(':', "-")
}

/// Parse an RFC 3339 timestamp. Accepts any valid RFC 3339 subsecond
/// precision; the result is truncated to milliseconds for consistency with
/// [`format`].
pub fn parse(s: &str) -> io::Result<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339)
        .map(truncate_to_millis)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid rfc3339 timestamp: {}", e)))
}

/// Inverse of [`format_fs_safe`]: restore the `:` characters in the time
/// portion and delegate to [`parse`].
pub fn parse_fs_safe(s: &str) -> io::Result<OffsetDateTime> {
    let (date, time) = s.split_once('T')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("invalid rfc3339 timestamp: missing 'T' in {}", s)))?;
    parse(&format!("{}T{}", date, time.replacen('-', ":", 2)))
}

fn truncate_to_millis(dt: OffsetDateTime) -> OffsetDateTime {
    let nanos = dt.nanosecond();
    let millis = nanos / 1_000_000;
    dt.replace_nanosecond(millis * 1_000_000).expect("valid nanosecond")
}

/// Serde adapter for `OffsetDateTime` fields serialized as spec-format RFC
/// 3339 strings. Use with `#[serde(with = "crate::timestamp::serde")]`.
pub mod serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    pub fn serialize<S: Serializer>(dt: &OffsetDateTime, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::format(*dt))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<OffsetDateTime, D::Error> {
        let s = String::deserialize(d)?;
        super::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    #[test]
    fn format_emits_millisecond_precision() {
        let dt = datetime!(2026-07-28 13:45:07.123456789 UTC);
        assert_eq!(format(dt), "2026-07-28T13:45:07.123Z");
    }

    #[test]
    fn format_pads_subseconds() {
        let dt = datetime!(2026-07-28 13:45:07.001 UTC);
        assert_eq!(format(dt), "2026-07-28T13:45:07.001Z");
    }

    #[test]
    fn format_zero_subseconds() {
        let dt = datetime!(2026-07-28 13:45:07 UTC);
        assert_eq!(format(dt), "2026-07-28T13:45:07.000Z");
    }

    #[test]
    fn parse_round_trips_spec_form() {
        let s = "2026-07-28T13:45:07.123Z";
        assert_eq!(format(parse(s).unwrap()), s);
    }

    #[test]
    fn parse_accepts_offset_and_normalizes_to_utc_millis() {
        let dt = parse("2026-07-28T13:45:07.123456+00:00").unwrap();
        assert_eq!(format(dt), "2026-07-28T13:45:07.123Z");
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse("not-a-timestamp").is_err());
    }

    #[test]
    fn parse_fs_safe_round_trips_format_fs_safe() {
        let dt = datetime!(2026-07-28 13:45:07.123 UTC);
        let s = format_fs_safe(dt);
        assert_eq!(s, "2026-07-28T13-45-07.123Z");
        assert_eq!(parse_fs_safe(&s).unwrap(), dt);
    }
}
