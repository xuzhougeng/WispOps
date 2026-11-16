//! Cron expressions: parsing, the next and latest runs in a zone, DST, and what is rejected.

use chrono_tz::Tz;
use wisp_ops_engine::cron::{CronError, CronField, parse};
use wisp_ops_engine::time::{parse_iso, to_iso};

fn at(text: &str) -> i64 {
    parse_iso(text).unwrap()
}

fn zone(name: &str) -> Tz {
    name.parse().unwrap()
}

/// The next `count` runs after `after`, as ISO strings.
fn runs(expression: &str, zone_name: &str, after: &str, count: usize) -> Vec<String> {
    parse(expression).unwrap().upcoming(zone(zone_name), at(after), count).into_iter().map(to_iso).collect()
}

fn latest(expression: &str, zone_name: &str, now: &str) -> Option<String> {
    parse(expression).unwrap().latest_at_or_before(zone(zone_name), at(now)).map(to_iso)
}

fn iso(texts: &[&str]) -> Vec<String> {
    texts.iter().map(|text| to_iso(at(text))).collect()
}

#[test]
fn parses_lists_ranges_steps_and_names() {
    let cron = parse("*/15 9-17/4 1,15 jan-MAR,Dec mon-fri").unwrap();
    assert_eq!(cron.minutes(), [0, 15, 30, 45]);
    assert_eq!(cron.hours(), [9, 13, 17]);
    assert_eq!(cron.days(), [1, 15]);
    assert_eq!(cron.months(), [1, 2, 3, 12]);
    assert_eq!(cron.weekdays(), [1, 2, 3, 4, 5]);
    assert!(cron.restricts_days() && cron.restricts_weekdays() && !cron.every_hour());
    // 7 is Sunday as 0 is; `5/20` runs from 5 to the end of the field; `?` is `*` in the day fields.
    assert_eq!(parse("0 0 * * 5-7").unwrap().weekdays(), [0, 5, 6]);
    assert_eq!(parse("0 0 * * 7").unwrap().weekdays(), [0]);
    assert_eq!(parse("5/20 * * * *").unwrap().minutes(), [5, 25, 45]);
    assert_eq!(parse("0 0 * * */2").unwrap().weekdays(), [0, 2, 4, 6]);
    let question = parse("0 0 ? * 1").unwrap();
    assert!(!question.restricts_days() && question.restricts_weekdays());
    assert!(!parse("  0   8 * *   *  ").unwrap().every_hour() && parse("0 * * * *").unwrap().every_hour());
}

#[test]
fn finds_ordinary_runs_in_the_task_zone() {
    assert_eq!(runs("0 8 * * *", "UTC", "2026-10-27T01:00:00Z", 2), iso(&["2026-10-27T08:00:00Z", "2026-10-28T08:00:00Z"]));
    // 08:00 in Shanghai is 00:00Z; strictly after the instant itself.
    assert_eq!(runs("0 8 * * *", "Asia/Shanghai", "2026-10-27T00:00:00Z", 1), iso(&["2026-10-28T00:00:00Z"]));
    // Every 20 minutes during working hours on weekdays: Friday 17:40 Shanghai, then Monday 09:00.
    assert_eq!(runs("*/20 9-17 * * 1-5", "Asia/Shanghai", "2026-10-30T09:30:00Z", 2), iso(&["2026-10-30T09:40:00Z", "2026-11-02T01:00:00Z"]));
    assert_eq!(latest("0 8 * * *", "UTC", "2026-10-27T08:00:00Z"), Some(to_iso(at("2026-10-27T08:00:00Z"))));
    assert_eq!(latest("0 8 * * *", "UTC", "2026-10-27T07:59:00Z"), Some(to_iso(at("2026-10-26T08:00:00Z"))));
    assert_eq!(latest("*/20 9-17 * * 1-5", "Asia/Shanghai", "2026-11-01T12:00:00Z"), Some(to_iso(at("2026-10-30T09:40:00Z"))));
    assert_eq!(runs("* * * * *", "UTC", "2026-10-27T01:00:30Z", 2), iso(&["2026-10-27T01:01:00Z", "2026-10-27T01:02:00Z"]));
}

#[test]
fn skips_months_without_the_day_and_finds_the_leap_day() {
    // The 31st: April and June have none.
    assert_eq!(runs("0 0 31 * *", "UTC", "2026-04-15T00:00:00Z", 2), iso(&["2026-05-31T00:00:00Z", "2026-07-31T00:00:00Z"]));
    // The 30th skips February.
    assert_eq!(runs("0 0 30 * *", "UTC", "2027-01-31T00:00:00Z", 1), iso(&["2027-03-30T00:00:00Z"]));
    assert_eq!(runs("0 12 29 2 *", "UTC", "2026-03-01T00:00:00Z", 2), iso(&["2028-02-29T12:00:00Z", "2032-02-29T12:00:00Z"]));
    assert_eq!(latest("0 12 29 2 *", "UTC", "2027-01-01T00:00:00Z"), Some(to_iso(at("2024-02-29T12:00:00Z"))));
    // 2100 is not a leap year.
    assert_eq!(runs("0 12 29 2 *", "UTC", "2097-01-01T00:00:00Z", 1), iso(&["2104-02-29T12:00:00Z"]));
    assert_eq!(runs("0 0 1 jan,jul *", "UTC", "2026-11-16T00:00:00Z", 2), iso(&["2027-01-01T00:00:00Z", "2027-07-01T00:00:00Z"]));
}

#[test]
fn matches_either_day_field_when_both_are_restricted_and_both_when_one_starts_with_a_star() {
    // The 10th or any Friday (2026-11-01 is a Sunday; the 10th a Tuesday).
    assert_eq!(runs("0 0 10 * 5", "UTC", "2026-11-01T00:00:00Z", 4), iso(&["2026-11-06T00:00:00Z", "2026-11-10T00:00:00Z", "2026-11-13T00:00:00Z", "2026-11-20T00:00:00Z"]));
    // `*/10` starts with a star, so the day must be the 1st, 11th, 21st or 31st and a Friday.
    assert_eq!(runs("0 0 */10 * 5", "UTC", "2026-11-01T00:00:00Z", 1), iso(&["2026-12-11T00:00:00Z"]));
    // Only the weekday restricted: every Monday.
    assert_eq!(runs("0 0 * * mon", "UTC", "2026-11-01T00:00:00Z", 2), iso(&["2026-11-02T00:00:00Z", "2026-11-09T00:00:00Z"]));
    // 29 February on a weekend (a star-led weekday, so both must match): Sunday 2032-02-29.
    assert_eq!(runs("0 0 29 2 */6", "UTC", "2026-11-01T00:00:00Z", 1), iso(&["2032-02-29T00:00:00Z"]));
}

#[test]
fn runs_a_skipped_fixed_time_once_after_the_jump_and_a_repeated_one_once() {
    // New York: 2026-03-08 02:00 EST jumps to 03:00 EDT; 2026-11-01 02:00 EDT falls back to 01:00 EST.
    let ny = "America/New_York";
    assert_eq!(runs("30 2 * * *", ny, "2026-03-07T00:00:00Z", 3), iso(&["2026-03-07T07:30:00Z", "2026-03-08T07:00:00Z", "2026-03-09T06:30:00Z"]));
    // Two slots inside the gap still run once, at the jump.
    assert_eq!(runs("0,30 2 * * *", ny, "2026-03-08T00:00:00Z", 3), iso(&["2026-03-08T07:00:00Z", "2026-03-09T06:00:00Z", "2026-03-09T06:30:00Z"]));
    // A slot repeated by the fall-back runs at its first occurrence only.
    assert_eq!(runs("30 1 * * *", ny, "2026-11-01T00:00:00Z", 2), iso(&["2026-11-01T05:30:00Z", "2026-11-02T06:30:00Z"]));
    assert_eq!(latest("30 1 * * *", ny, "2026-11-01T06:45:00Z"), Some(to_iso(at("2026-11-01T05:30:00Z"))));
    // Europe/Berlin jumps 02:00 → 03:00 on 2026-03-29.
    assert_eq!(runs("15 2 * * *", "Europe/Berlin", "2026-03-28T12:00:00Z", 2), iso(&["2026-03-29T01:00:00Z", "2026-03-30T00:15:00Z"]));
}

#[test]
fn follows_the_clock_through_dst_when_the_schedule_is_for_every_hour() {
    let ny = "America/New_York";
    // 02:30 does not exist on 2026-03-08: 01:30 EST, then 03:30 EDT.
    assert_eq!(runs("30 * * * *", ny, "2026-03-08T06:00:00Z", 2), iso(&["2026-03-08T06:30:00Z", "2026-03-08T07:30:00Z"]));
    // 01:30 happens twice on 2026-11-01 and runs both times.
    assert_eq!(runs("30 * * * *", ny, "2026-11-01T04:00:00Z", 4), iso(&["2026-11-01T04:30:00Z", "2026-11-01T05:30:00Z", "2026-11-01T06:30:00Z", "2026-11-01T07:30:00Z"]));
    assert_eq!(latest("30 * * * *", ny, "2026-11-01T06:45:00Z"), Some(to_iso(at("2026-11-01T06:30:00Z"))));
}

#[test]
fn rejects_what_cannot_be_evaluated() {
    assert_eq!(parse("0 8 * *"), Err(CronError::Fields(4)));
    assert_eq!(parse("0 0 8 * * *"), Err(CronError::Fields(6)));
    assert_eq!(parse(""), Err(CronError::Fields(0)));
    assert_eq!(parse("@daily"), Err(CronError::Macro { name: "@daily".into(), instead: Some("0 0 * * *") }));
    assert_eq!(parse("@reboot"), Err(CronError::Macro { name: "@reboot".into(), instead: None }));
    assert_eq!(parse("60 * * * *"), Err(CronError::Range { field: CronField::Minute, token: "60".into() }));
    assert_eq!(parse("0 24 * * *"), Err(CronError::Range { field: CronField::Hour, token: "24".into() }));
    assert_eq!(parse("0 0 0 * *"), Err(CronError::Range { field: CronField::Day, token: "0".into() }));
    assert_eq!(parse("0 0 * 13 *"), Err(CronError::Range { field: CronField::Month, token: "13".into() }));
    assert_eq!(parse("0 0 * * 8"), Err(CronError::Range { field: CronField::Weekday, token: "8".into() }));
    assert_eq!(parse("0 0 * * 1-9"), Err(CronError::Range { field: CronField::Weekday, token: "1-9".into() }));
    assert_eq!(parse("5-1 * * * *"), Err(CronError::Backwards { field: CronField::Minute, token: "5-1".into() }));
    assert_eq!(parse("*/0 * * * *"), Err(CronError::Step { field: CronField::Minute, token: "*/0".into() }));
    assert_eq!(parse("*/x * * * *"), Err(CronError::Step { field: CronField::Minute, token: "*/x".into() }));
    for unsupported in ["0 8 L * *", "0 8 15W * *", "0 8 * * MON#2", "0 8 * * 5L", "? * * * *", "0 8 1,,2 * *", "0 8 * * monday", "0 8 * jan- *", "-1 * * * *"] {
        assert!(matches!(parse(unsupported), Err(CronError::Syntax { .. })), "{unsupported}: {:?}", parse(unsupported));
    }
    assert_eq!(parse("0 0 30 2 *"), Err(CronError::Never));
    assert_eq!(parse("0 0 31 4,6,9,11 *"), Err(CronError::Never));
    assert!(parse("0 0 31 2 1").is_ok(), "both day fields restricted: every Monday in February");
    assert_eq!(CronError::Range { field: CronField::Hour, token: "24".into() }.to_string(), "hour field \"24\" is outside 0-23");
    assert_eq!(CronError::Macro { name: "@daily".into(), instead: Some("0 0 * * *") }.to_string(), "\"@daily\" is not supported; write \"0 0 * * *\"");
}
