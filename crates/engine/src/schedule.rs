//! Wall-clock arithmetic for task schedules: when a daily or weekly task was last due in its
//! zone, whether the application's timer should run it now, and whether it skipped a slot.
//! Cron expressions are evaluated by [`crate::cron`] in the same zone. Every function takes `now`
//! (epoch milliseconds).

use std::str::FromStr;

use chrono::{Datelike, NaiveDate, TimeZone, Timelike};
use chrono_tz::Tz;

use crate::config::TaskSchedule;
use crate::cron;
use crate::time::{parse_iso, to_iso};

/// Calendar fields of an instant in a zone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZonedParts {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    /// ISO weekday, Monday 1 … Sunday 7.
    pub weekday: u32,
}

/// A wall-clock time without a weekday.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WallClock {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
}

/// Look up an IANA zone by name (case-insensitive, as the plugin's runtime was).
pub fn parse_zone(time_zone: &str) -> Result<Tz, String> {
    Tz::from_str(time_zone).or_else(|_| Tz::from_str_insensitive(time_zone)).map_err(|_| format!("Invalid time zone specified: {time_zone}"))
}

/// Calendar fields of an instant in a zone. Fails for an unknown zone.
pub fn zoned_parts(ms: i64, time_zone: &str) -> Result<ZonedParts, String> {
    let zone = parse_zone(time_zone)?;
    let at = zone.timestamp_millis_opt(ms).single().ok_or_else(|| "time out of range".to_string())?;
    Ok(ZonedParts { year: at.year(), month: at.month(), day: at.day(), hour: at.hour(), minute: at.minute(), weekday: at.weekday().number_from_monday() })
}

/// Milliseconds of a calendar time read as UTC (`Date.UTC`), tolerating out-of-range days.
fn utc_ms(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> i64 {
    let first = NaiveDate::from_ymd_opt(year, month.clamp(1, 12), 1).unwrap_or_default();
    let days = i64::from(first.num_days_from_ce()) - 719_163 + i64::from(day) - 1;
    days * 86_400_000 + i64::from(hour) * 3_600_000 + i64::from(minute) * 60_000
}

/// The instant of a wall-clock time in a zone; on an ambiguous DST hour, the first occurrence.
pub fn zoned_to_utc(wall: WallClock, time_zone: &str) -> Result<i64, String> {
    let naive = utc_ms(wall.year, wall.month, wall.day, wall.hour, wall.minute);
    let mut guess = naive;
    for _ in 0..3 {
        let z = zoned_parts(guess, time_zone)?;
        let diff = naive - utc_ms(z.year, z.month, z.day, z.hour, z.minute);
        if diff == 0 { break }
        guess += diff;
    }
    Ok(guess)
}

fn hour_minute(daily: &str) -> Option<(u32, u32)> {
    let (hour, minute) = daily.split_once(':')?;
    Some((hour.parse().ok()?, minute.parse().ok()?))
}

/// A schedule's cron expression with its zone, when it has one.
fn cron_of(schedule: &TaskSchedule, default_zone: &str) -> Result<Option<(cron::Cron, Tz)>, String> {
    let Some(expression) = &schedule.cron else { return Ok(None) };
    let parsed = cron::parse(expression).map_err(|error| format!("cron \"{expression}\": {error}"))?;
    Ok(Some((parsed, parse_zone(schedule.time_zone.as_deref().unwrap_or(default_zone))?)))
}

/// How long before a slot a run still covers it (clock skew, a manual run): five minutes, or for
/// a cron schedule that runs more often, half the time since its previous slot.
fn cover_ms(schedule: &TaskSchedule, default_zone: &str, due: i64) -> Result<i64, String> {
    let Some((cron, zone)) = cron_of(schedule, default_zone)? else { return Ok(COVER_MS) };
    Ok(cron.latest_at_or_before(zone, due - 1).map_or(COVER_MS, |previous| COVER_MS.min((due - previous) / 2)))
}

const COVER_MS: i64 = 5 * 60_000;

/// The latest instant at or before `now` when a daily, weekly or cron schedule was due; `None` for intervals.
pub fn previous_due(schedule: &TaskSchedule, default_zone: &str, now: i64) -> Result<Option<i64>, String> {
    if let Some((cron, zone)) = cron_of(schedule, default_zone)? { return Ok(cron.latest_at_or_before(zone, now)) }
    let Some(daily) = &schedule.daily else { return Ok(None) };
    let (hour, minute) = hour_minute(daily).ok_or_else(|| format!("invalid daily time \"{daily}\""))?;
    let zone = schedule.time_zone.as_deref().unwrap_or(default_zone);
    let mut probe = now;
    for _ in 0..9 {
        let z = zoned_parts(probe, zone)?;
        let due = zoned_to_utc(WallClock { year: z.year, month: z.month, day: z.day, hour, minute }, zone)?;
        if due <= now && (schedule.weekdays.is_empty() || schedule.weekdays.contains(&z.weekday)) { return Ok(Some(due)) }
        probe -= 86_400_000;
    }
    Ok(None)
}

/// How late a run may be before it is called missed.
pub const MISSED_GRACE_MS: i64 = 30 * 60_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissedRun {
    /// ISO time of the slot that was examined.
    pub due_at: Option<String>,
    pub missed: bool,
}

/// Whether a scheduled task appears to have skipped its latest slot: no run recorded at or after
/// the due time once the grace period passed. Intervals compare against the last run; a cron
/// schedule examines its latest slot at least the grace period old, so one that runs more often
/// than the grace period still reports a miss.
pub fn missed_run(schedule: &TaskSchedule, default_zone: &str, last_run: Option<&str>, now: i64) -> Result<MissedRun, String> {
    let last = last_run.and_then(parse_iso);
    if let Some(every) = schedule.every_minutes {
        let Some(last) = last else { return Ok(MissedRun { due_at: None, missed: false }) };
        let interval = every as i64 * 60_000;
        let due = last + interval;
        return Ok(MissedRun { due_at: Some(to_iso(due)), missed: now - due > MISSED_GRACE_MS.max(interval) });
    }
    let examined = if schedule.cron.is_some() { now - MISSED_GRACE_MS - 1 } else { now };
    let Some(due) = previous_due(schedule, default_zone, examined)? else { return Ok(MissedRun { due_at: None, missed: false }) };
    // A run slightly before the slot (clock skew, a manual run) still covers it.
    let covered = last.is_some_and(|last| last >= due - cover_ms(schedule, default_zone, due).unwrap_or(COVER_MS));
    Ok(MissedRun { due_at: Some(to_iso(due)), missed: !covered && now - due > MISSED_GRACE_MS })
}

/// Whether the application's timer should run a task now. Daily, weekly and cron slots count from
/// the moment the timer was enabled, so enabling after today's slot waits for tomorrow's; an
/// interval counts from the later of the last run and enabling.
pub fn due_now(schedule: &TaskSchedule, default_zone: &str, last_run: Option<&str>, enabled_at: &str, now: i64) -> Result<bool, String> {
    let last = last_run.and_then(parse_iso);
    let enabled = parse_iso(enabled_at).unwrap_or(now);
    if let Some(every) = schedule.every_minutes { return Ok(now >= last.unwrap_or(0).max(enabled) + every as i64 * 60_000) }
    let Some(due) = previous_due(schedule, default_zone, now)? else { return Ok(false) };
    if due < enabled { return Ok(false) }
    let cover = cover_ms(schedule, default_zone, due)?;
    Ok(last.is_none_or(|last| last < due - cover))
}

/// The next instant the application's timer would run a task; `None` on demand.
pub fn next_due(schedule: &TaskSchedule, default_zone: &str, last_run: Option<&str>, enabled_at: &str, now: i64) -> Result<Option<i64>, String> {
    let last = last_run.and_then(parse_iso);
    let enabled = parse_iso(enabled_at).unwrap_or(now);
    if let Some(every) = schedule.every_minutes { return Ok(Some(now.max(last.unwrap_or(0).max(enabled) + every as i64 * 60_000))) }
    if schedule.daily.is_none() && schedule.cron.is_none() { return Ok(None) }
    if due_now(schedule, default_zone, last_run, enabled_at, now)? { return Ok(Some(now)) }
    if let Some((cron, zone)) = cron_of(schedule, default_zone)? { return Ok(cron.next_after(zone, now)) }
    // The earliest slot after now: probe forward one day at a time and take the first strictly later slot.
    for ahead in 1..=8 {
        if let Some(candidate) = previous_due(schedule, default_zone, now + ahead * 86_400_000)?
            && candidate > now
        {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

/// A schedule in words: `daily 08:30 Asia/Shanghai`, `every 30 min`, `on demand`.
pub fn describe_schedule(schedule: Option<&TaskSchedule>, default_zone: &str) -> String {
    let Some(schedule) = schedule else { return "on demand".to_string() };
    let zone = schedule.time_zone.as_deref().unwrap_or(default_zone);
    if let Some(daily) = &schedule.daily {
        if schedule.weekdays.is_empty() { return format!("daily {daily} {zone}") }
        return format!("{daily} {zone} on ISO weekdays {}", schedule.weekdays.iter().map(u32::to_string).collect::<Vec<_>>().join(","));
    }
    if let Some(cron) = &schedule.cron { return format!("cron \"{cron}\" {zone}") }
    match schedule.every_minutes {
        Some(every) => format!("every {every} min"),
        None => "on demand".to_string(),
    }
}
