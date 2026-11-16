//! Five-field cron expressions (minute hour day-of-month month day-of-week) evaluated on the wall
//! clock of an IANA zone, as Vixie cron reads them: lists (`1,15`), ranges (`1-5`), steps (`*/15`,
//! `0-30/10`, `5/15` = `5-max/15`), month and weekday names (`JAN`, `mon-fri`), 0 or 7 for Sunday,
//! and `?` as `*` in the two day fields. When both day fields are restricted a day matches either;
//! when either starts with `*` both must match. `L`, `W`, `#`, seconds, years and `@daily` macros
//! are rejected with a message saying what to write instead.
//!
//! Daylight saving time: a schedule with a fixed hour runs once a day whatever the clock does — a
//! time skipped when clocks go forward runs at the first moment after the jump, a time repeated
//! when they go back runs at its first occurrence only. A schedule for every hour (`*` hours)
//! follows the clock as it reads: skipped minutes do not run, repeated minutes run both times.

use std::fmt;

use chrono::{Datelike, Duration, LocalResult, NaiveDate, NaiveDateTime, TimeZone, Timelike};
use chrono_tz::Tz;

/// One of the five fields, for messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CronField {
    Minute,
    Hour,
    Day,
    Month,
    Weekday,
}

impl CronField {
    const ALL: [CronField; 5] = [CronField::Minute, CronField::Hour, CronField::Day, CronField::Month, CronField::Weekday];

    pub fn as_str(self) -> &'static str {
        match self {
            CronField::Minute => "minute",
            CronField::Hour => "hour",
            CronField::Day => "day-of-month",
            CronField::Month => "month",
            CronField::Weekday => "day-of-week",
        }
    }

    /// The values the field takes; the day of the week also takes 7 for Sunday.
    pub fn bounds(self) -> (u32, u32) {
        match self {
            CronField::Minute => (0, 59),
            CronField::Hour => (0, 23),
            CronField::Day => (1, 31),
            CronField::Month => (1, 12),
            CronField::Weekday => (0, 7),
        }
    }
}

/// Why an expression cannot be evaluated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CronError {
    /// Not five fields; the count found.
    Fields(usize),
    /// A `@name` macro; its five-field equivalent when there is one.
    Macro { name: String, instead: Option<&'static str> },
    /// Not a number, name, `*`, list, range or step.
    Syntax { field: CronField, token: String },
    /// A value outside the field's bounds.
    Range { field: CronField, token: String },
    /// A range whose end is before its start.
    Backwards { field: CronField, token: String },
    /// A step that is not a positive number.
    Step { field: CronField, token: String },
    /// Valid, but no date ever matches (31 February).
    Never,
}

impl fmt::Display for CronError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CronError::Fields(count) => write!(f, "needs five fields (minute hour day-of-month month day-of-week), found {count}; seconds and years are not supported"),
            CronError::Macro { name, instead: Some(instead) } => write!(f, "\"{name}\" is not supported; write \"{instead}\""),
            CronError::Macro { name, instead: None } => write!(f, "\"{name}\" is not supported; write five fields"),
            CronError::Syntax { field, token } => write!(f, "{} field \"{token}\" is not a number, name, *, list (,), range (-) or step (/)", field.as_str()),
            CronError::Range { field, token } => {
                let (min, max) = field.bounds();
                write!(f, "{} field \"{token}\" is outside {min}-{max}", field.as_str())
            }
            CronError::Backwards { field, token } => write!(f, "{} field range \"{token}\" ends before it starts", field.as_str()),
            CronError::Step { field, token } => write!(f, "{} field step \"{token}\" must be a positive number", field.as_str()),
            CronError::Never => write!(f, "never matches a date (the day does not exist in the chosen months)"),
        }
    }
}

/// A parsed expression; the sets are bit masks (weekday bit 0 is Sunday).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cron {
    minutes: u64,
    hours: u32,
    days: u32,
    months: u32,
    weekdays: u32,
    /// The day-of-month field starts with `*` or `?`.
    day_star: bool,
    /// The day-of-week field starts with `*` or `?`.
    weekday_star: bool,
}

const MONTHS: [&str; 12] = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];
const WEEKDAYS: [&str; 7] = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];
/// How far a search looks: one Gregorian cycle and a year, so 29 February on a given weekday is found.
const HORIZON_DAYS: i64 = 146_097 + 366;

fn value(field: CronField, text: &str, token: &str) -> Result<u32, CronError> {
    let names: &[&str] = match field {
        CronField::Month => &MONTHS,
        CronField::Weekday => &WEEKDAYS,
        _ => &[],
    };
    if let Some(index) = names.iter().position(|name| name.eq_ignore_ascii_case(text)) {
        return Ok(index as u32 + if field == CronField::Month { 1 } else { 0 });
    }
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) { return Err(CronError::Syntax { field, token: token.to_string() }) }
    let number: u32 = text.parse().map_err(|_| CronError::Range { field, token: token.to_string() })?;
    let (min, max) = field.bounds();
    if number < min || number > max { return Err(CronError::Range { field, token: token.to_string() }) }
    Ok(number)
}

fn parse_field(field: CronField, text: &str) -> Result<u64, CronError> {
    let (min, max) = field.bounds();
    let mut mask = 0u64;
    for item in text.split(',') {
        let (base, step) = match item.split_once('/') {
            Some((base, step)) => {
                let step: u32 = step.parse().ok().filter(|step| *step > 0).ok_or_else(|| CronError::Step { field, token: item.to_string() })?;
                (base, Some(step))
            }
            None => (item, None),
        };
        let star = base == "*" || (base == "?" && matches!(field, CronField::Day | CronField::Weekday));
        let (start, end) = if star {
            (min, if field == CronField::Weekday { 6 } else { max })
        } else if let Some((from, to)) = base.split_once('-') {
            let (from, to) = (value(field, from, item)?, value(field, to, item)?);
            if to < from { return Err(CronError::Backwards { field, token: item.to_string() }) }
            (from, to)
        } else {
            let from = value(field, base, item)?;
            // `5/15` runs from 5 to the end of the field (Saturday for the day of the week).
            (from, if step.is_none() { from } else if field == CronField::Weekday { 6 } else { max })
        };
        let mut at = start;
        while at <= end {
            // Sunday is 0 and 7.
            mask |= 1 << if field == CronField::Weekday && at == 7 { 0 } else { at };
            at += step.unwrap_or(1);
        }
    }
    Ok(mask)
}

/// What a `@macro` means in five fields.
fn macro_equivalent(name: &str) -> Option<&'static str> {
    match name.to_ascii_lowercase().as_str() {
        "@yearly" | "@annually" => Some("0 0 1 1 *"),
        "@monthly" => Some("0 0 1 * *"),
        "@weekly" => Some("0 0 * * 0"),
        "@daily" | "@midnight" => Some("0 0 * * *"),
        "@hourly" => Some("0 * * * *"),
        _ => None,
    }
}

/// Parse an expression; fails for anything that cannot be evaluated, including one that never runs.
pub fn parse(expression: &str) -> Result<Cron, CronError> {
    let fields: Vec<&str> = expression.split_whitespace().collect();
    if let [single] = fields.as_slice()
        && single.starts_with('@')
    {
        return Err(CronError::Macro { name: single.to_string(), instead: macro_equivalent(single) });
    }
    if fields.len() != 5 { return Err(CronError::Fields(fields.len())) }
    let mut masks = [0u64; 5];
    for (slot, (field, text)) in masks.iter_mut().zip(CronField::ALL.into_iter().zip(&fields)) {
        *slot = parse_field(field, text)?;
    }
    let star = |text: &str| text.starts_with('*') || text.starts_with('?');
    let cron = Cron { minutes: masks[0], hours: masks[1] as u32, days: masks[2] as u32, months: masks[3] as u32, weekdays: masks[4] as u32, day_star: star(fields[2]), weekday_star: star(fields[4]) };
    let start = NaiveDate::from_ymd_opt(2000, 1, 1).unwrap_or_default();
    if cron.next_date(start, start + Duration::days(HORIZON_DAYS)).is_none() { return Err(CronError::Never) }
    Ok(cron)
}

fn members(mask: u64, min: u32, max: u32) -> Vec<u32> {
    (min..=max).filter(|bit| mask & (1 << bit) != 0).collect()
}

impl Cron {
    pub fn minutes(&self) -> Vec<u32> {
        members(self.minutes, 0, 59)
    }

    pub fn hours(&self) -> Vec<u32> {
        members(u64::from(self.hours), 0, 23)
    }

    pub fn days(&self) -> Vec<u32> {
        members(u64::from(self.days), 1, 31)
    }

    pub fn months(&self) -> Vec<u32> {
        members(u64::from(self.months), 1, 12)
    }

    /// Days of the week, Sunday 0 … Saturday 6.
    pub fn weekdays(&self) -> Vec<u32> {
        members(u64::from(self.weekdays), 0, 6)
    }

    /// Whether the day-of-month field restricts the days (it does not start with `*`).
    pub fn restricts_days(&self) -> bool {
        !self.day_star
    }

    /// Whether the day-of-week field restricts the days (it does not start with `*`).
    pub fn restricts_weekdays(&self) -> bool {
        !self.weekday_star
    }

    /// Every hour of the day: such a schedule follows the clock through DST changes.
    pub fn every_hour(&self) -> bool {
        self.hours == (1 << 24) - 1
    }

    /// Whether a calendar date is one the schedule runs on.
    pub fn matches_date(&self, date: NaiveDate) -> bool {
        if self.months & (1 << date.month()) == 0 { return false }
        let day = self.days & (1 << date.day()) != 0;
        let weekday = self.weekdays & (1 << date.weekday().num_days_from_sunday()) != 0;
        if self.day_star || self.weekday_star { day && weekday } else { day || weekday }
    }

    /// The first matching date from `from` (inclusive) to `limit`, skipping months that do not match.
    fn next_date(&self, mut date: NaiveDate, limit: NaiveDate) -> Option<NaiveDate> {
        while date <= limit {
            if self.months & (1 << date.month()) == 0 {
                let (year, month) = if date.month() == 12 { (date.year() + 1, 1) } else { (date.year(), date.month() + 1) };
                date = NaiveDate::from_ymd_opt(year, month, 1)?;
                continue;
            }
            if self.matches_date(date) { return Some(date) }
            date = date.succ_opt()?;
        }
        None
    }

    /// The last matching date from `from` (inclusive) back to `limit`.
    fn previous_date(&self, mut date: NaiveDate, limit: NaiveDate) -> Option<NaiveDate> {
        while date >= limit {
            if self.months & (1 << date.month()) == 0 {
                date = NaiveDate::from_ymd_opt(date.year(), date.month(), 1)?.pred_opt()?;
                continue;
            }
            if self.matches_date(date) { return Some(date) }
            date = date.pred_opt()?;
        }
        None
    }

    /// The instants (epoch ms) the schedule runs at on a local date, ascending, after the DST rules above.
    pub fn instants_on(&self, date: NaiveDate, zone: Tz) -> Vec<i64> {
        let every_hour = self.every_hour();
        let mut instants = Vec::new();
        for hour in self.hours() {
            for minute in self.minutes() {
                let Some(wall) = date.and_hms_opt(hour, minute, 0) else { continue };
                match zone.from_local_datetime(&wall) {
                    LocalResult::Single(at) => instants.push(at.timestamp_millis()),
                    LocalResult::Ambiguous(first, second) => {
                        instants.push(first.timestamp_millis());
                        if every_hour { instants.push(second.timestamp_millis()) }
                    }
                    LocalResult::None => {
                        if !every_hour && let Some(at) = after_gap(wall, zone) { instants.push(at) }
                    }
                }
            }
        }
        instants.sort_unstable();
        instants.dedup();
        instants
    }

    /// The first run strictly after `after`.
    pub fn next_after(&self, zone: Tz, after: i64) -> Option<i64> {
        let today = zone.timestamp_millis_opt(after).single()?.date_naive();
        // A day back: a time skipped on the previous local date may land just after midnight.
        let (mut date, limit) = (today.pred_opt()?, today + Duration::days(HORIZON_DAYS));
        loop {
            date = self.next_date(date, limit)?;
            if let Some(at) = self.instants_on(date, zone).into_iter().find(|at| *at > after) { return Some(at) }
            date = date.succ_opt()?;
        }
    }

    /// The latest run at or before `now`.
    pub fn latest_at_or_before(&self, zone: Tz, now: i64) -> Option<i64> {
        let today = zone.timestamp_millis_opt(now).single()?.date_naive();
        let (mut date, limit) = (today.succ_opt()?, today - Duration::days(HORIZON_DAYS));
        loop {
            date = self.previous_date(date, limit)?;
            if let Some(at) = self.instants_on(date, zone).into_iter().rev().find(|at| *at <= now) { return Some(at) }
            date = date.pred_opt()?;
        }
    }

    /// The next `count` runs strictly after `after`.
    pub fn upcoming(&self, zone: Tz, after: i64, count: usize) -> Vec<i64> {
        let mut runs = Vec::with_capacity(count);
        let mut at = after;
        while runs.len() < count {
            let Some(next) = self.next_after(zone, at) else { break };
            runs.push(next);
            at = next;
        }
        runs
    }
}

/// The first existing instant after a wall-clock time that a forward jump skipped.
fn after_gap(wall: NaiveDateTime, zone: Tz) -> Option<i64> {
    let mut probe = wall.with_second(0)?;
    for _ in 0..24 * 60 {
        probe += Duration::minutes(1);
        if let Some(at) = zone.from_local_datetime(&probe).earliest() { return Some(at.timestamp_millis()) }
    }
    None
}
