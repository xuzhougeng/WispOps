//! A cron expression in the window's words: what it means, why it cannot be used, and its next
//! few runs in the task's zone. Evaluation is the engine's (`wisp_ops_engine::cron`); this only words it.

use crate::i18n::{is_english, t};
use wisp_ops_engine::cron::{self, Cron, CronError, CronField};
use wisp_ops_engine::schedule;

const WEEKDAYS: [&str; 7] = ["周日", "周一", "周二", "周三", "周四", "周五", "周六"];
const MONTHS: [&str; 12] = ["1 月", "2 月", "3 月", "4 月", "5 月", "6 月", "7 月", "8 月", "9 月", "10 月", "11 月", "12 月"];

fn field_name(field: CronField) -> &'static str {
    t(match field {
        CronField::Minute => "分",
        CronField::Hour => "时",
        CronField::Day => "日",
        CronField::Month => "月",
        CronField::Weekday => "周",
    })
}

/// Why an expression cannot be used, in a sentence a person can act on.
pub fn error(error: &CronError) -> String {
    match error {
        CronError::Fields(count) => tf!("需要 5 个用空格分开的字段（分 时 日 月 周），现在是 {count} 个；不支持秒和年。", "Needs five fields separated by spaces (minute hour day month weekday); found {count}. Seconds and years are not supported."),
        CronError::Macro { name, instead: Some(instead) } => tf!("不支持 {name}，请写成 {instead}。", "{name} is not supported; write {instead}."),
        CronError::Macro { name, instead: None } => tf!("不支持 {name}，请写 5 个字段。", "{name} is not supported; write five fields."),
        CronError::Syntax { field, token } => tf!("「{}」字段的 {token} 看不懂：只能用数字、名称（MON、JAN）、*、列表（,）、范围（-）和步长（/）。", "{} field {token} is not understood: use numbers, names (MON, JAN), *, lists (,), ranges (-) and steps (/).", field_name(*field)),
        CronError::Range { field, token } => {
            let (min, max) = field.bounds();
            tf!("「{}」字段的 {token} 超出 {min}–{max}。", "{} field {token} is outside {min}–{max}.", field_name(*field))
        }
        CronError::Backwards { field, token } => tf!("「{}」字段的范围 {token} 结尾比开头小。", "{} field range {token} ends before it starts.", field_name(*field)),
        CronError::Step { field, token } => tf!("「{}」字段的步长 {token} 应是正整数。", "{} field step {token} must be a positive number.", field_name(*field)),
        CronError::Never => t("这个表达式永远不会运行：所选的月份里没有这一天。").to_string(),
    }
}

fn join(items: Vec<String>) -> String {
    items.join(if is_english() { ", " } else { "、" })
}

/// Runs of three or more consecutive values as `a–b` (`dash` between them).
fn compress(values: &[u32], dash: &str, name: impl Fn(u32) -> String) -> String {
    let mut parts = Vec::new();
    let mut index = 0;
    while index < values.len() {
        let mut end = index;
        while end + 1 < values.len() && values[end + 1] == values[end] + 1 { end += 1 }
        if end - index >= 2 {
            parts.push(format!("{}{dash}{}", name(values[index]), name(values[end])));
        } else {
            parts.extend(values[index..=end].iter().map(|value| name(*value)));
        }
        index = end + 1;
    }
    join(parts)
}

/// The step of `values` when they are every `step`-th from 0 and the step divides `cycle`.
fn even_step(values: &[u32], cycle: u32) -> Option<u32> {
    let step = *values.get(1)?;
    (values[0] == 0 && step > 1 && cycle.is_multiple_of(step) && values.len() as u32 == cycle / step && values.iter().enumerate().all(|(index, value)| *value == index as u32 * step)).then_some(step)
}

fn numbers(values: &[u32]) -> String {
    compress(values, "–", |value| value.to_string())
}

fn time_words(cron: &Cron) -> String {
    let (minutes, hours) = (cron.minutes(), cron.hours());
    let every_minute = minutes.len() == 60;
    let all_hours = hours.len() == 24;
    if all_hours {
        if every_minute { return t("每分钟").to_string() }
        if let Some(step) = even_step(&minutes, 60) { return tf!("每 {step} 分钟", "every {step} minutes") }
        return tf!("每小时第 {} 分", "at minute {} of every hour", numbers(&minutes));
    }
    if minutes.len() * hours.len() <= 6 {
        let times = hours.iter().flat_map(|hour| minutes.iter().map(move |minute| format!("{hour:02}:{minute:02}"))).collect();
        return join(times);
    }
    if minutes.len() == 1
        && let Some(step) = even_step(&hours, 24)
    {
        return tf!("每 {step} 小时（第 {} 分）", "every {step} hours at minute {}", minutes[0]);
    }
    let hour_list = numbers(&hours);
    if every_minute { return tf!("{hour_list} 点内每分钟", "every minute during hours {hour_list}") }
    if let Some(step) = even_step(&minutes, 60) { return tf!("{hour_list} 点内每 {step} 分钟", "every {step} minutes during hours {hour_list}") }
    tf!("{hour_list} 点的第 {} 分", "at minute {} past hours {hour_list}", numbers(&minutes))
}

/// The days of the week by name, without `每` / `on`: `周一至周五`, `Mon–Fri`.
fn weekday_names(weekdays: &[u32]) -> String {
    // Monday first, as the week is read here.
    let monday_first: Vec<u32> = weekdays.iter().map(|day| if *day == 0 { 7 } else { *day }).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    compress(&monday_first, if is_english() { "–" } else { "至" }, |day| t(WEEKDAYS[day as usize % 7]).to_string())
}

fn day_words(cron: &Cron) -> Option<String> {
    let (days, weekdays) = (cron.days(), cron.weekdays());
    let some_days = (days.len() < 31).then(|| tf!("每月 {} 日", "on day {} of the month", numbers(&days)));
    let names = (weekdays.len() < 7).then(|| weekday_names(&weekdays));
    let some_weekdays = names.as_ref().map(|names| tf!("每{names}", "on {names}"));
    if cron.restricts_days() && cron.restricts_weekdays() {
        // Either matches: one that allows every day makes every day.
        return match (some_days, some_weekdays) {
            (Some(days), Some(weekdays)) => Some(tf!("{days}或{weekdays}", "{days} or {weekdays}")),
            _ => None,
        };
    }
    match (some_days, some_weekdays) {
        (Some(days), Some(_)) => Some(tf!("{days}且逢{}", "{days} if it is {}", names.unwrap_or_default())),
        (days, weekdays) => days.or(weekdays),
    }
}

/// What an expression means: `周一至周五 08:30`, `every 15 minutes on Mon–Fri in Jan, Jul`.
pub fn describe(cron: &Cron) -> String {
    let months = cron.months();
    let time = time_words(cron);
    // A clock time wants its days said; "every 15 minutes" says them already.
    let clock = time.starts_with(|c: char| c.is_ascii_digit());
    if is_english() {
        let days = day_words(cron).or_else(|| clock.then(|| "every day".to_string()));
        let months = (months.len() < 12).then(|| compress(&months, "–", |month| t(MONTHS[month as usize - 1]).to_string()));
        return [Some(time), days, months.map(|months| format!("in {months}"))].into_iter().flatten().collect::<Vec<_>>().join(" ");
    }
    let days = day_words(cron);
    match (months.len() < 12).then(|| format!("{} 月", numbers(&months))) {
        // `2 月 29 日 12:00`, `1–3、7 月的每周日 03:00`, `1、7 月 每 15 分钟`.
        Some(months) => match days {
            Some(days) if days.starts_with("每月 ") => format!("{months} {} {time}", days.trim_start_matches("每月 ")),
            Some(days) => format!("{months}的{days} {time}"),
            None if clock => format!("{months}每天 {time}"),
            None => format!("{months} {time}"),
        },
        None => match days {
            Some(days) => format!("{days} {time}"),
            None if clock => format!("每天 {time}"),
            None => time,
        },
    }
}

/// A run time in the task's zone: `11-17 周二 08:30`.
pub fn run_time(ms: i64, zone: &str) -> String {
    match schedule::zoned_parts(ms, zone) {
        Ok(parts) => format!("{:02}-{:02} {} {:02}:{:02}", parts.month, parts.day, t(WEEKDAYS[parts.weekday as usize % 7]), parts.hour, parts.minute),
        Err(_) => String::new(),
    }
}

/// For the task form: what an expression means and its next `count` runs after `now` in `zone`,
/// or why it cannot be used.
pub fn preview(expression: &str, zone: &str, now: i64, count: usize) -> Result<(String, Vec<String>), String> {
    let parsed = cron::parse(expression).map_err(|why| error(&why))?;
    let tz = schedule::parse_zone(zone)?;
    Ok((describe(&parsed), parsed.upcoming(tz, now, count).into_iter().map(|at| run_time(at, zone)).collect()))
}

/// A weekday's one-character Chinese name as the window's language writes it short: `一` or `Mon`.
pub fn weekday_short(name: &str) -> &'static str {
    let english = crate::i18n::is_english();
    match name {
        "一" => if english { "Mon" } else { "一" },
        "二" => if english { "Tue" } else { "二" },
        "三" => if english { "Wed" } else { "三" },
        "四" => if english { "Thu" } else { "四" },
        "五" => if english { "Fri" } else { "五" },
        "六" => if english { "Sat" } else { "六" },
        _ => if english { "Sun" } else { "日" },
    }
}

#[cfg(test)]
mod tests {
    use super::{describe, error, preview};
    use wisp_ops_engine::cron::parse;

    fn words(expression: &str) -> String {
        describe(&parse(expression).unwrap())
    }

    #[test]
    fn describes_expressions_in_chinese() {
        assert_eq!(words("30 8 * * *"), "每天 08:30");
        assert_eq!(words("30 8 * * 1-5"), "每周一至周五 08:30");
        assert_eq!(words("0 8,20 * * sat,sun"), "每周六、周日 08:00、20:00");
        assert_eq!(words("*/15 * * * *"), "每 15 分钟");
        assert_eq!(words("* * * * *"), "每分钟");
        assert_eq!(words("5 * * * *"), "每小时第 5 分");
        assert_eq!(words("0 */2 * * *"), "每 2 小时（第 0 分）");
        assert_eq!(words("*/10 9-17 * * 1-5"), "每周一至周五 9–17 点内每 10 分钟");
        assert_eq!(words("0 0 1,15 * *"), "每月 1、15 日 00:00");
        assert_eq!(words("0 0 10 * 5"), "每月 10 日或每周五 00:00");
        assert_eq!(words("0 0 */10 * 5"), "每月 1、11、21、31 日且逢周五 00:00");
        assert_eq!(words("0 12 29 2 *"), "2 月 29 日 12:00");
        assert_eq!(words("0 3 * 1-3,7 0"), "1–3、7 月的每周日 03:00");
        assert_eq!(words("*/15 * * 1,7 *"), "1、7 月 每 15 分钟");
    }

    #[test]
    fn words_errors_and_previews() {
        assert!(error(&parse("0 8 * *").unwrap_err()).contains("现在是 4 个"));
        assert!(error(&parse("@daily").unwrap_err()).contains("0 0 * * *"));
        assert!(error(&parse("0 25 * * *").unwrap_err()).contains("0–23"));
        let (meaning, runs) = preview("0 8 * * *", "Asia/Shanghai", 0, 3).unwrap();
        assert_eq!(meaning, "每天 08:00");
        // The epoch is 08:00 in Shanghai itself; runs are strictly after it.
        assert_eq!(runs, ["01-02 周五 08:00", "01-03 周六 08:00", "01-04 周日 08:00"]);
        assert!(preview("0 8 31 2 *", "UTC", 0, 3).unwrap_err().contains("永远不会运行"));
    }
}
