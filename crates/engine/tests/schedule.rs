//! Schedule arithmetic in IANA zones (`schedule.spec.ts`, plus the timer functions).

use wisp_ops_engine::config::TaskSchedule;
use wisp_ops_engine::schedule::{MissedRun, WallClock, ZonedParts, describe_schedule, due_now, missed_run, next_due, previous_due, zoned_parts, zoned_to_utc};
use wisp_ops_engine::time::{parse_iso, to_iso};

fn at(text: &str) -> i64 {
    parse_iso(text).unwrap()
}

fn daily(time: &str) -> TaskSchedule {
    TaskSchedule { daily: Some(time.to_string()), ..TaskSchedule::default() }
}

fn every(minutes: u64) -> TaskSchedule {
    TaskSchedule { every_minutes: Some(minutes), ..TaskSchedule::default() }
}

fn cron() -> TaskSchedule {
    TaskSchedule { cron: Some("0 8 * * *".to_string()), ..TaskSchedule::default() }
}

fn wall(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> WallClock {
    WallClock { year, month, day, hour, minute }
}

#[test]
fn converts_wall_clock_times_in_a_zone_including_dst_transitions() {
    assert_eq!(zoned_to_utc(wall(2026, 10, 27, 8, 30), "Asia/Shanghai").unwrap(), at("2026-10-27T00:30:00Z"));
    assert_eq!(zoned_to_utc(wall(2026, 10, 27, 8, 30), "UTC").unwrap(), at("2026-10-27T08:30:00Z"));
    // New York leaves DST on 2026-11-01: 08:30 local is 12:30Z before and 13:30Z after.
    assert_eq!(zoned_to_utc(wall(2026, 10, 31, 8, 30), "America/New_York").unwrap(), at("2026-10-31T12:30:00Z"));
    assert_eq!(zoned_to_utc(wall(2026, 11, 2, 8, 30), "America/New_York").unwrap(), at("2026-11-02T13:30:00Z"));
    // The ambiguous hour resolves to its first occurrence.
    assert_eq!(zoned_to_utc(wall(2026, 11, 1, 1, 30), "America/New_York").unwrap(), at("2026-11-01T05:30:00Z"));
    assert_eq!(zoned_parts(at("2026-10-27T00:30:00Z"), "Asia/Shanghai").unwrap(), ZonedParts { year: 2026, month: 10, day: 27, hour: 8, minute: 30, weekday: 2 });
    assert_eq!(zoned_parts(at("2026-11-01T12:00:00Z"), "asia/shanghai").unwrap().weekday, 7);
    assert!(zoned_parts(0, "Not/AZone").is_err());
}

#[test]
fn finds_the_latest_daily_and_weekly_slot_at_or_before_now() {
    let now = at("2026-10-27T01:00:00Z"); // Tuesday 09:00 in Shanghai
    let due = |schedule: &TaskSchedule, zone: &str| previous_due(schedule, zone, now).unwrap();
    assert_eq!(due(&daily("08:30"), "Asia/Shanghai"), Some(at("2026-10-27T00:30:00Z")));
    assert_eq!(due(&daily("09:30"), "Asia/Shanghai"), Some(at("2026-10-26T01:30:00Z")));
    assert_eq!(due(&daily("09:00"), "Asia/Shanghai"), Some(now));
    assert_eq!(due(&TaskSchedule { time_zone: Some("UTC".to_string()), ..daily("08:30") }, "Asia/Shanghai"), Some(at("2026-10-26T08:30:00Z")));
    // Weekly on Mondays and Fridays: the Monday slot was the last one.
    assert_eq!(due(&TaskSchedule { weekdays: vec![1, 5], ..daily("08:30") }, "Asia/Shanghai"), Some(at("2026-10-26T00:30:00Z")));
    assert_eq!(due(&TaskSchedule { weekdays: vec![2], ..daily("10:00") }, "Asia/Shanghai"), Some(at("2026-10-20T02:00:00Z")));
    assert_eq!(due(&cron(), "UTC"), None);
    assert_eq!(due(&every(30), "UTC"), None);
    assert!(previous_due(&daily("08:30"), "Not/AZone", now).is_err());
}

#[test]
fn reports_a_missed_slot_only_after_the_grace_period_and_when_no_run_covered_it() {
    let due = at("2026-10-27T00:30:00Z");
    let schedule = TaskSchedule { time_zone: Some("Asia/Shanghai".to_string()), ..daily("08:30") };
    let minutes = |n: i64| n * 60_000;
    let missed = |schedule: &TaskSchedule, last: Option<i64>, now: i64| missed_run(schedule, "UTC", last.map(to_iso).as_deref(), now).unwrap();
    assert_eq!(missed(&schedule, None, due + minutes(10)), MissedRun { due_at: Some(to_iso(due)), missed: false });
    assert_eq!(missed(&schedule, None, due + minutes(45)), MissedRun { due_at: Some(to_iso(due)), missed: true });
    assert!(!missed(&schedule, Some(due + minutes(2)), due + minutes(45)).missed);
    assert!(!missed(&schedule, Some(due - minutes(3)), due + minutes(45)).missed);
    assert!(missed(&schedule, Some(due - 86_400_000), due + minutes(45)).missed);
    assert!(!missed(&every(15), None, due).missed);
    assert!(!missed(&every(15), Some(due), due + minutes(20)).missed);
    assert_eq!(missed(&every(15), Some(due), due + minutes(50)), MissedRun { due_at: Some(to_iso(due + minutes(15))), missed: true });
    assert_eq!(missed(&cron(), None, due + 86_400_000), MissedRun { due_at: None, missed: false });
}

#[test]
fn runs_daily_slots_once_and_only_after_the_timer_was_enabled() {
    let zone = "Asia/Shanghai";
    let slot = at("2026-10-27T00:30:00Z"); // 08:30 in Shanghai
    let schedule = daily("08:30");
    let due = |last: Option<i64>, enabled: i64, now: i64| due_now(&schedule, zone, last.map(to_iso).as_deref(), &to_iso(enabled), now).unwrap();
    let next = |last: Option<i64>, enabled: i64, now: i64| next_due(&schedule, zone, last.map(to_iso).as_deref(), &to_iso(enabled), now).unwrap();
    let enabled_before = slot - 3_600_000;
    assert!(!due(None, enabled_before, slot - 60_000));
    assert!(due(None, enabled_before, slot));
    assert!(due(None, enabled_before, slot + 3_600_000));
    // A run at (or just before) the slot covers it.
    assert!(!due(Some(slot + 1000), enabled_before, slot + 3_600_000));
    assert!(!due(Some(slot - 2 * 60_000), enabled_before, slot + 60_000));
    assert!(due(Some(slot - 86_400_000), enabled_before, slot + 60_000));
    // Enabling after today's slot waits for tomorrow's.
    assert!(!due(None, slot + 60_000, slot + 3_600_000));
    assert!(due(None, slot + 60_000, slot + 86_400_000));
    assert_eq!(next(None, enabled_before, slot - 60_000), Some(slot));
    assert_eq!(next(None, enabled_before, slot + 5000), Some(slot + 5000));
    assert_eq!(next(Some(slot + 1000), enabled_before, slot + 5000), Some(slot + 86_400_000));
    // Weekly: only the listed weekdays (2026-10-27 is a Tuesday).
    let fridays = TaskSchedule { weekdays: vec![5], ..daily("08:30") };
    assert_eq!(next_due(&fridays, zone, None, &to_iso(slot), slot + 1000).unwrap(), Some(at("2026-10-30T00:30:00Z")));
    assert!(!due_now(&fridays, zone, None, &to_iso(enabled_before), slot + 1000).unwrap());
}

#[test]
fn counts_intervals_from_the_later_of_the_last_run_and_enabling_and_never_runs_cron() {
    let t0 = at("2026-10-27T00:00:00Z");
    let minutes = |n: i64| n * 60_000;
    let schedule = every(30);
    let due = |last: Option<i64>, enabled: i64, now: i64| due_now(&schedule, "UTC", last.map(to_iso).as_deref(), &to_iso(enabled), now).unwrap();
    assert!(!due(None, t0, t0 + minutes(29)));
    assert!(due(None, t0, t0 + minutes(30)));
    assert!(!due(Some(t0 + minutes(20)), t0, t0 + minutes(45)));
    assert!(due(Some(t0 + minutes(20)), t0, t0 + minutes(50)));
    assert!(!due(Some(t0 - minutes(120)), t0, t0 + minutes(10)));
    assert_eq!(next_due(&schedule, "UTC", None, &to_iso(t0), t0 + minutes(10)).unwrap(), Some(t0 + minutes(30)));
    assert_eq!(next_due(&schedule, "UTC", None, &to_iso(t0), t0 + minutes(40)).unwrap(), Some(t0 + minutes(40)));
    // An unreadable enabling time counts from now; an unreadable last run is no run.
    assert!(!due_now(&schedule, "UTC", Some("garbage"), "garbage", t0).unwrap());
    assert!(!due_now(&cron(), "UTC", None, &to_iso(t0), t0 + 86_400_000 * 3).unwrap());
    assert_eq!(next_due(&cron(), "UTC", None, &to_iso(t0), t0).unwrap(), None);
}

#[test]
fn describes_schedules() {
    assert_eq!(describe_schedule(None, "UTC"), "on demand");
    assert_eq!(describe_schedule(Some(&daily("08:30")), "Asia/Shanghai"), "daily 08:30 Asia/Shanghai");
    assert_eq!(describe_schedule(Some(&TaskSchedule { weekdays: vec![1, 5], time_zone: Some("UTC".to_string()), ..daily("08:30") }), "Asia/Shanghai"), "08:30 UTC on ISO weekdays 1,5");
    assert_eq!(describe_schedule(Some(&cron()), "UTC"), "cron \"0 8 * * *\" UTC");
    assert_eq!(describe_schedule(Some(&every(30)), "UTC"), "every 30 min");
}
