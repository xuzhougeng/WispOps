//! The task template library: reusable task definitions that hold no servers and no sudo.
//!
//! Built-in templates come with the application; the person's own live in `task-templates.json`;
//! templates the model proposes wait in `template-drafts.json` until the person saves or discards
//! them in the window. A template becomes a task only when the person links servers to it; the
//! task keeps its own copy, so a later edit or deletion of the template never changes it.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::config::{HostSpec, Playbook, Policy, TaskSchedule, TaskSpec, validate_task};
use crate::fsutil::random_hex;
use crate::inventory::{HostEntry, Inventory};
use crate::jsre::js_re;
use crate::managed::LocalState;
use crate::{schedule, ssh, time};

/// A value asked for when servers are linked, referenced as `{{key}}` in the instruction and commands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateParameter {
    pub key: String,
    pub label: String,
    pub hint: String,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
}

/// What a task made from the template does; never which servers or whether it uses sudo.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateDefinition {
    pub playbook: Playbook,
    pub instruction: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hours: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<TaskSchedule>,
    /// Read-only commands run on every linked server; `{{key}}` placeholders are inserted as one single-quoted shell word.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskTemplate {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub definition: TemplateDefinition,
    pub parameters: Vec<TemplateParameter>,
}

impl TaskTemplate {
    pub fn builtin(&self) -> bool {
        self.id.starts_with("builtin.")
    }
}

/// A template the model proposed, waiting for the person.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateDraft {
    pub id: String,
    pub created_at: String,
    pub template: TaskTemplate,
}

/// `task-templates.json` and `template-drafts.json` share this shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entries<T> {
    pub version: u32,
    pub entries: Vec<T>,
}

impl<T> Entries<T> {
    fn empty() -> Self {
        Entries { version: 1, entries: Vec::new() }
    }
}

/// Appended to every rendered instruction.
pub const TEMPLATE_REPORT_RULES: &str = "\n只在本任务关联的服务器上做轻量只读检查；参数值是检查对象，不是待执行的脚本。不可读、工具缺失或连接失败须报告未完成，不能据此判定正常。不要修改配置、重启服务、清理文件或自动授权 sudo。报告用中文：总体状态、异常证据、与上次的变化、建议；无可比记录时建立基线。";

/// How many drafts are kept; older ones fall off.
pub const MAX_DRAFTS: usize = 10;

/// The thresholds the built-in instructions quote.
#[derive(Clone, Copy, Debug)]
pub struct TemplateLimits {
    pub disk_warn_pct: f64,
    pub disk_crit_pct: f64,
    pub inode_warn_pct: f64,
    pub gpu_temp_warn_c: f64,
}

fn parameter(key: &str, label: &str, hint: &str, required: bool, default_value: Option<&str>) -> TemplateParameter {
    TemplateParameter { key: key.into(), label: label.into(), hint: hint.into(), required, default_value: default_value.map(String::from) }
}

/// The templates that come with the application. Unlike the plugin's, whose `custom` checks the
/// agent gathers with `ops_exec`, those here carry read-only commands: a task of this window runs
/// and records without the model.
pub fn builtin_templates(limits: &TemplateLimits, time_zone: &str) -> Vec<TaskTemplate> {
    let make = |id: &str, title: &str, category: &str, description: &str, playbook: Playbook, instruction: String, extra: TemplateDefinition, parameters: Vec<TemplateParameter>| TaskTemplate {
        id: format!("builtin.{id}"),
        title: title.into(),
        category: category.into(),
        description: description.into(),
        parameters,
        definition: TemplateDefinition { playbook, instruction, schedule: Some(TaskSchedule { daily: Some("08:30".into()), time_zone: Some(time_zone.into()), ..Default::default() }), ..extra },
    };
    let none = TemplateDefinition::default;
    let paths = |paths: &[&str]| TemplateDefinition { paths: paths.iter().map(|path| path.to_string()).collect(), ..Default::default() };
    let commands = |commands: &[&str]| TemplateDefinition { commands: commands.iter().map(|command| command.to_string()).collect(), ..Default::default() };
    let l = limits;
    vec![
        make("health", "服务器健康巡检", "基础运维", "负载、内存、磁盘、inode、失败服务和内核异常。", Playbook::Inspect, format!("分析已采集的健康数据，检查负载、内存、磁盘、inode、失败服务、OOM 和内核错误。磁盘使用率达到 {}% 告警、{}% 紧急；inode 达到 {}% 告警。结合每核负载和任务情况判断，不把一次高负载直接当成故障。", l.disk_warn_pct, l.disk_crit_pct, l.inode_warn_pct), none(), vec![]),
        make("disk", "磁盘空间诊断", "基础运维", "定位大目录、增长来源及已删除但仍占用的文件。", Playbook::Disk, "分析所选目录的容量和 inode、主要占用、近期增长及已删除仍被进程占用的文件。区分日志、缓存、原始数据和分析结果，给出带依据的清理候选，不执行删除。".into(), paths(&["/"]), vec![]),
        make("space", "目录空间占用", "基础运维", "用可逐层展开的方块图展示各目录占用，找出最占空间的文件夹。", Playbook::Space, "分析所选路径下各级目录的占用（同一文件系统内，默认展开 5 层），指出占用最多的目录及其中最大的子目录、直接堆放大量文件的目录，以及与上次相比增长明显的目录。区分日志、缓存、原始数据、分析结果和用户主目录；非 root 运行时无权读取的目录会使统计偏小，须说明缺口。只给出带依据的清理建议，不执行删除。".into(), paths(&["/"]), vec![]),
        make("new-files", "新增文件分析", "数据管理", "按目录、属主和文件类型统计新增数据与空间增长。", Playbook::NewFiles, "分析指定目录在任务设定天数内新增或修改的文件，按目录、属主、类型和体积汇总。区分测序原始数据、分析结果、可再生中间文件和日志；用途未知时标记待确认。".into(), TemplateDefinition { days: Some(1), ..paths(&["/var/log"]) }, vec![]),
        make("security", "安全排查", "安全", "检查认证异常、监听端口、进程和持久化迹象。", Playbook::Security, "分析任务设定回溯窗口内的认证、登录、监听端口、异常进程、外连和持久化证据。区分失败认证、正常连接和成功登录；单凭扫描或失败登录不能判定入侵。不展示密码、令牌或私钥。".into(), TemplateDefinition { hours: Some(24), ..none() }, vec![]),
        make("services", "关键服务可用性", "应用服务", "检查指定服务是否运行、是否异常退出及近期错误。", Playbook::Custom, "关注服务名称：{{services}}。根据任务只读命令采集的 systemd 状态和有界的近期日志，区分未安装、主动停止、管理方式不同和意外失败。不能仅凭 systemd inactive 判定实际服务不可用；必要时用只读 ops_exec 交叉检查监听端口。".into(), commands(&["systemctl is-active $(printf '%s' {{services}} | tr ',' ' ')", "systemctl status --no-pager --lines=20 $(printf '%s' {{services}} | tr ',' ' ')"]), vec![parameter("services", "服务名称", "例如 nginx、postgresql；多个名称用英文逗号或空格分隔。", true, None)]),
        make("web", "网站与证书检查", "应用服务", "检查网页连通性、HTTP 状态及 TLS 证书到期时间。", Playbook::Custom, "需要检查的网址：{{urls}}。任务从关联服务器发起有超时限制的只读 HTTP HEAD 请求并读取 TLS 证书有效期；据此检查状态码、响应耗时与证书到期时间。禁止提交表单或调用会改变数据的接口，不跟随到未指定主机的重定向。证书不足 30 天提示关注，不足 7 天标记紧急；权限不足或无法验证时说明原因，不自动续签。".into(), commands(&["printf '%s\\n' {{urls}} | while read -r u; do [ -n \"$u\" ] && curl -sS -I -m 10 -w 'HTTP %{http_code} in %{time_total}s\\n' \"$u\" | grep -E '^HTTP'; done", "printf '%s\\n' {{urls}} | sed -n 's#^https://##p' | cut -d/ -f1 | cut -d: -f1 | while read -r h; do printf '%s ' \"$h\"; echo | openssl s_client -connect \"$h:443\" -servername \"$h\" 2>/dev/null | openssl x509 -noout -enddate; done"]), vec![parameter("urls", "检查网址", "填写 http(s) URL；每行一个，不要包含口令、令牌或有写入作用的接口。", true, None)]),
        make("containers", "容器运行状态", "应用服务", "查看容器退出、重启次数和健康检查失败。", Playbook::Custom, "关注的容器：{{containers}}。根据任务只读命令采集的容器状态、重启次数和健康检查结果，区分一次性已完成容器和长期服务异常；Docker 不可用或无权限时说明。不要读取容器环境变量中的秘密，不自动重启、拉取镜像或清理容器。".into(), commands(&["docker ps -a --format 'table {{.Names}}\\t{{.Status}}\\t{{.RunningFor}}'", "docker ps -a --filter health=unhealthy --filter status=restarting --format '{{.Names}} {{.Status}}'", "docker inspect --format '{{.Name}} restarts={{.RestartCount}} status={{.State.Status}}' $(docker ps -aq)"]), vec![parameter("containers", "关注容器", "可填写容器名称；留空检查已有容器。", false, Some("所有已有容器"))]),
        make("backups", "备份时效检查", "数据管理", "检查备份是否按期产出、大小是否异常及失败记录。", Playbook::Custom, "备份位置：{{locations}}；预期产出频率：{{cadence}}。根据任务只读命令列出的最新备份时间和大小判断，先确认时区和预期频率再判断延迟。不要读取备份内容或访问凭据，不执行备份或恢复。文件存在只说明产物存在，不能据此宣称备份可恢复或完整性已验证。".into(), commands(&["ls -lt --time-style=long-iso {{locations}} | head -n 20", "find {{locations}} -maxdepth 2 -type f -mtime -2 -printf '%TY-%Tm-%Td %TH:%TM %s %p\\n' | sort -r | head -n 20"]), vec![parameter("locations", "备份目录", "备份产物所在的本机绝对路径。", true, None), parameter("cadence", "预期备份频率", "例如每天一次、每周日一次。", true, Some("每天一次"))]),
        make("logs", "日志异常汇总", "应用服务", "汇总近期错误类型、发生次数与首次/最后出现时间。", Playbook::Custom, "日志范围：{{logs}}。任务读取最近 24 小时的有界日志片段（日志文件读取末尾 2000 行，服务读取 journal），据此汇总 error、fatal、OOM、超时和异常堆栈的类型、计数以及首次/最后出现时间。采样计数不可宣称是完整统计；遮蔽密码、令牌及请求中的敏感信息。".into(), commands(&["if [ -f {{logs}} ]; then tail -n 2000 {{logs}} | grep -i -E 'error|fatal|oom|timeout|exception' | tail -n 200; else journalctl -u {{logs}} --since '-24h' --no-pager -p warning | tail -n 200; fi"]), vec![parameter("logs", "日志路径或服务名称", "例如 /var/log/nginx/error.log，或 nginx.service。", true, None)]),
        make("long-running", "长时间运行任务警告", "计算集群", "列出运行超过阈值的进程和调度器作业，区分正常长作业与疑似卡死。", Playbook::Custom, "运行时长阈值：{{hours}} 小时；忽略的进程名或用户：{{ignore}}。根据任务只读命令列出的运行时长超过阈值的进程（及 Slurm 运行中的作业），按用户和命令汇总，给出运行时长、CPU、内存和进程状态。排除 systemd、sshd、内核线程等长期服务进程。长时间运行本身不是故障：正常的长作业（比对、组装、训练）只需列出；CPU 长期为 0、状态 D/Z、父进程已退出或日志长时间无更新的进程标记为疑似卡死并给出依据。不要终止进程、取消作业或发送信号。".into(), commands(&["ps -eo pid,user,etimes,stat,pcpu,pmem,rss,comm,args --sort=-etimes | awk -v h={{hours}} 'NR==1 || $3 >= h*3600' | head -n 50", "squeue -t R -o '%i %u %M %l %j' 2>/dev/null | head -n 50"]), vec![parameter("hours", "运行时长阈值（小时）", "超过该时长的进程和作业会被列出。", true, Some("24")), parameter("ignore", "忽略的进程名或用户", "例如 jupyter、rstudio；多个用逗号分隔，留空不忽略。", false, Some("无"))]),
        make("low-memory", "低内存警告", "基础运维", "可用内存或 swap 低于阈值时告警，并指出占用最多的进程。", Playbook::Custom, "可用内存告警阈值：{{availPct}}%；swap 使用率告警阈值：{{swapPct}}%。根据任务只读命令采集的 free -m、/proc/meminfo 的 MemAvailable 和 Committed_AS、按 RSS 排序的前 10 个进程以及最近 24 小时的 OOM 记录判断。以 MemAvailable 而不是 MemFree 判断：page cache 可回收，cache 高不算低内存。报告可用内存与 swap 比例、是否发生过 OOM kill、占用最多的进程和用户，以及与上次相比的变化；低于阈值告警，发生 OOM kill 或可用内存低于阈值一半标记紧急。不要清理缓存、终止进程或调整 swap。".into(), commands(&["free -m", "grep -E 'MemTotal|MemAvailable|Committed_AS|SwapTotal|SwapFree' /proc/meminfo", "ps -eo pid,user,rss,pmem,etimes,comm --sort=-rss | head -n 11", "journalctl -k --since '-24h' --no-pager | grep -i -E 'out of memory|oom-kill' | tail -n 20"]), vec![parameter("availPct", "可用内存告警阈值（%）", "可用内存占总内存的比例低于该值时告警。", true, Some("15")), parameter("swapPct", "swap 使用率告警阈值（%）", "swap 已用比例高于该值时告警；无 swap 的服务器说明不适用。", true, Some("50"))]),
        make("gpu-jobs", "GPU 与作业队列", "计算集群", "查看 GPU 资源、温度及 Slurm 等调度器队列。", Playbook::Inspect, format!("根据已采集的资源数据检查 GPU 利用率、显存、占用进程与温度（达到 {}°C 提示），GPU 空闲本身不是故障。若有 Slurm/PBS/SGE/LSF，查看节点不可用原因和排队作业；区分资源等待与故障，不提交、取消作业或启动计算程序。无对应硬件或调度器时明确不适用。", l.gpu_temp_warn_c), none(), vec![]),
    ]
}

fn placeholder() -> &'static regex::Regex {
    js_re!(r"\{\{([A-Za-z][A-Za-z0-9_]*)\}\}")
}

/// Replace every `{{key}}`; a key the template does not define is an error.
fn substitute(text: &str, prepared: &BTreeMap<String, String>, word: impl Fn(&str) -> String, missing: impl Fn(&str) -> String) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for found in placeholder().captures_iter(text) {
        let (whole, key) = (found.get(0).expect("match"), &found[1]);
        let value = prepared.get(key).ok_or_else(|| missing(key))?;
        out.push_str(&text[last..whole.start()]);
        out.push_str(&word(value));
        last = whole.end();
    }
    out.push_str(&text[last..]);
    Ok(out)
}

/// Each parameter's value: given, else its default, else empty. Strict rendering requires the required ones.
fn prepare(template: &TaskTemplate, values: &BTreeMap<String, String>, strict: bool) -> Result<BTreeMap<String, String>, String> {
    let mut prepared = BTreeMap::new();
    for parameter in &template.parameters {
        let value = values.get(&parameter.key).or(parameter.default_value.as_ref()).map(String::as_str).unwrap_or("");
        if value.chars().count() > 4000 || value.contains('\0') { return Err(format!("{} 格式不正确。", parameter.label)) }
        if strict && parameter.required && value.trim().is_empty() { return Err(format!("请填写{}。", parameter.label)) }
        let shown = if !value.trim().is_empty() { value.trim().to_string() } else if strict { "未指定".to_string() } else { format!("【待填写：{}】", parameter.label) };
        prepared.insert(parameter.key.clone(), shown);
    }
    Ok(prepared)
}

/// The instruction with parameter values in place, followed by the report rules.
pub fn render_template(template: &TaskTemplate, values: &BTreeMap<String, String>, strict: bool) -> Result<String, String> {
    let prepared = prepare(template, values, strict)?;
    Ok(substitute(&template.definition.instruction, &prepared, str::to_string, |key| format!("模板引用了未定义的参数 {key}。"))? + TEMPLATE_REPORT_RULES)
}

/// One POSIX shell word; the quoting the SSH runner uses.
pub fn shell_word(value: &str) -> String {
    ssh::shell_quote(value)
}

/// The template's commands with parameter values inserted as quoted shell words, so a value can
/// never add a second command; the result is still classified read-only before it is saved.
pub fn render_template_commands(template: &TaskTemplate, values: &BTreeMap<String, String>, strict: bool) -> Result<Vec<String>, String> {
    if template.definition.commands.is_empty() { return Ok(vec![]) }
    let prepared = prepare(template, values, strict)?;
    template.definition.commands.iter().map(|command| substitute(command, &prepared, shell_word, |key| format!("模板命令引用了未定义的参数 {key}。"))).collect()
}

/// What a task made from the template says and runs, with the instruction and commands as the
/// person left them in the form (they may have edited the template's), filled in strictly.
pub fn fill(template: &TaskTemplate, instruction: &str, commands: &[String], values: &BTreeMap<String, String>) -> Result<(String, Vec<String>), String> {
    let edited = TaskTemplate { definition: TemplateDefinition { instruction: instruction.to_string(), commands: commands.to_vec(), ..template.definition.clone() }, ..template.clone() };
    Ok((render_template(&edited, values, true)?, render_template_commands(&edited, values, true)?))
}

const PROBE_HOST: &str = "template-validation";

/// Check a task with the template's definition against one stand-in server, as a saved task is checked.
fn check_as_task(spec: TaskSpec, extra_read: &HashSet<String>) -> Result<(), String> {
    validate_task(&spec)?;
    Inventory::new(vec![HostEntry::from(HostSpec::named(PROBE_HOST))], BTreeMap::new(), Policy::default(), vec![spec], extra_read).map(|_| ())
}

fn string_field<'a>(raw: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    raw.get(key).and_then(Value::as_str).filter(|value| value.chars().count() <= 1000).ok_or_else(|| "模板信息不正确。".to_string())
}

/// Validate a template from anywhere (the window, the model, a file): shape, the same collector,
/// schedule and path rules as a concrete task, and read-only commands in their rendered form.
pub fn validate_template(value: &Value, extra_read: &HashSet<String>) -> Result<TaskTemplate, String> {
    let raw = value.as_object().ok_or("模板信息不正确。")?;
    let id = raw.get("id").and_then(Value::as_str).unwrap_or("");
    if !js_re!(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$").is_match(id) || id.starts_with("builtin.") || id == "all" { return Err("模板标识无效或使用了预设保留名称。".into()) }
    let (title, description, category) = (string_field(raw, "title")?, string_field(raw, "description")?, string_field(raw, "category")?);
    if title.trim().is_empty() || category.trim().is_empty() { return Err("请填写模板标题和分类。".into()) }
    let definition = raw.get("definition").and_then(Value::as_object).ok_or("模板信息不正确。")?;
    if definition.contains_key("targets") || definition.contains_key("sudo") { return Err("模板不保存服务器关联或 sudo 授权。".into()) }
    let mut parsed: TemplateDefinition = serde_json::from_value(Value::Object(definition.clone())).map_err(|error| format!("模板定义不正确：{error}"))?;
    if parsed.playbook == Playbook::Script { return Err("模板不支持检查脚本，请改用内置检查或只读命令。".into()) }
    if parsed.instruction.trim().is_empty() || parsed.instruction.chars().count() > 30000 { return Err("请填写巡查规则，最多 30000 字符。".into()) }
    parsed.commands = parsed.commands.iter().map(|command| command.trim().to_string()).collect();
    if parsed.commands.iter().any(String::is_empty) { return Err("只读命令不能为空行。".into()) }
    let task = |commands: Vec<String>| TaskSpec { name: PROBE_HOST.into(), targets: PROBE_HOST.into(), playbook: parsed.playbook, instruction: Some(parsed.instruction.clone()), schedule: parsed.schedule.clone(), paths: parsed.paths.clone(), days: parsed.days, hours: parsed.hours, commands, ..Default::default() };
    // Collector, schedule and path rules first; commands are checked below in rendered form.
    let named = |error: String| error.replace(&format!("task \"{PROBE_HOST}\""), "模板");
    validate_task(&task(parsed.commands.clone())).and_then(|()| check_as_task(task(vec![]), extra_read)).map_err(named)?;
    if let Some(zone) = parsed.schedule.as_ref().and_then(|schedule| schedule.time_zone.as_deref()) {
        schedule::parse_zone(zone).map_err(|_| "模板时区无效。".to_string())?;
    }
    let listed = raw.get("parameters").and_then(Value::as_array).filter(|list| list.len() <= 20).ok_or("模板参数格式不正确。")?;
    let mut seen = HashSet::new();
    let mut parameters = vec![];
    for item in listed {
        let bad = || "模板参数格式不正确或重复。".to_string();
        let parameter: TemplateParameter = serde_json::from_value(item.clone()).map_err(|_| bad())?;
        if !js_re!(r"^[A-Za-z][A-Za-z0-9_]*$").is_match(&parameter.key) || !seen.insert(parameter.key.clone()) || parameter.label.trim().is_empty() || parameter.default_value.as_ref().is_some_and(|value| value.chars().count() > 4000) { return Err(bad()) }
        parameters.push(parameter);
    }
    let template = TaskTemplate { id: id.into(), title: title.trim().into(), description: description.into(), category: category.trim().into(), definition: parsed.clone(), parameters };
    render_template(&template, &BTreeMap::new(), false)?;
    // A `{{key}}` placeholder is one quoted word once servers are linked, so classify the rendered form the way a saved task is classified.
    let rendered = render_template_commands(&template, &BTreeMap::new(), false)?;
    if !rendered.is_empty() { check_as_task(task(rendered), extra_read).map_err(named)? }
    Ok(template)
}

/// The shape of a stored file; the full rules ran when each entry was written.
fn read_entries<T: serde::de::DeserializeOwned>(value: Value, what: &str, id: fn(&T) -> &str) -> Result<Entries<T>, String> {
    let read: Entries<T> = serde_json::from_value(value).map_err(|error| format!("Invalid {what}: {error}"))?;
    if read.version != 1 { return Err(format!("Invalid {what}")) }
    let mut ids = HashSet::new();
    if !read.entries.iter().all(|entry| ids.insert(id(entry).to_string())) { return Err(format!("{what}: 模板标识重复。")) }
    Ok(read)
}

/// The person's own templates.
pub fn template_store(data_dir: &Path) -> LocalState<Entries<TaskTemplate>> {
    LocalState::new(data_dir.join("task-templates.json"), Entries::empty, |value| {
        let read = read_entries::<TaskTemplate>(value, "task template library", |template| &template.id)?;
        if read.entries.iter().any(TaskTemplate::builtin) { return Err("模板标识无效或使用了预设保留名称。".into()) }
        Ok(read)
    })
}

/// Templates the model proposed. Only the person moves one into the library, by saving it in the window.
pub fn draft_store(data_dir: &Path) -> LocalState<Entries<TemplateDraft>> {
    LocalState::new(data_dir.join("template-drafts.json"), Entries::empty, |value| read_entries::<TemplateDraft>(value, "template drafts", |draft| &draft.id))
}

/// Queue a validated draft; a newer draft with the same template id replaces the older one, and only the latest few are kept.
pub fn add_template_draft(data_dir: &Path, template: &Value, extra_read: &HashSet<String>, now_ms: i64) -> Result<TemplateDraft, String> {
    let draft = TemplateDraft { id: random_hex::<16>()?, created_at: time::to_iso(now_ms), template: validate_template(template, extra_read)? };
    let store = draft_store(data_dir);
    let read = store.read()?;
    store.change(&read.revision, |mut state| {
        state.entries.retain(|entry| entry.template.id != draft.template.id);
        state.entries.push(draft.clone());
        let surplus = state.entries.len().saturating_sub(MAX_DRAFTS);
        state.entries.drain(..surplus);
        Ok(state)
    })?;
    Ok(draft)
}

/// Remove a draft; one already gone is no error.
pub fn discard_draft(data_dir: &Path, id: &str) -> Result<(), String> {
    let store = draft_store(data_dir);
    let read = store.read()?;
    if !read.value.entries.iter().any(|draft| draft.id == id) { return Ok(()) }
    store.change(&read.revision, |mut state| {
        state.entries.retain(|draft| draft.id != id);
        Ok(state)
    })
}

/// Save a template to the library: a new id, or (`edit`) one already there. A reviewed draft leaves the queue once it is in.
pub fn save_template(data_dir: &Path, template: &Value, edit: bool, draft: Option<&str>, extra_read: &HashSet<String>) -> Result<TaskTemplate, String> {
    let template = validate_template(template, extra_read)?;
    let store = template_store(data_dir);
    let read = store.read()?;
    store.change(&read.revision, |mut state| {
        let exists = state.entries.iter().any(|entry| entry.id == template.id);
        if edit && !exists { return Err("模板已被删除，请刷新后重试。".into()) }
        if !edit && exists { return Err("模板标识已存在。".into()) }
        state.entries.retain(|entry| entry.id != template.id);
        state.entries.push(template.clone());
        Ok(state)
    })?;
    if let Some(draft) = draft { let _ = discard_draft(data_dir, draft); }
    Ok(template)
}

/// Delete one of the person's templates; built-in ones cannot be. Tasks made from it keep their copy.
pub fn delete_template(data_dir: &Path, id: &str) -> Result<(), String> {
    let store = template_store(data_dir);
    let read = store.read()?;
    store.change(&read.revision, |mut state| {
        if !state.entries.iter().any(|entry| entry.id == id) { return Err("预设不可删除，或模板已不存在。".into()) }
        state.entries.retain(|entry| entry.id != id);
        Ok(state)
    })
}

/// The built-in templates and then the person's own, as the window and the model see the library.
pub fn library(data_dir: &Path, limits: &TemplateLimits, time_zone: &str) -> Result<Vec<TaskTemplate>, String> {
    let mut all = builtin_templates(limits, time_zone);
    all.extend(template_store(data_dir).read()?.value.entries);
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::{RiskLevel, classify_command};
    use serde_json::json;

    const LIMITS: TemplateLimits = TemplateLimits { disk_warn_pct: 80., disk_crit_pct: 90., inode_warn_pct: 80., gpu_temp_warn_c: 85. };

    fn none() -> HashSet<String> {
        HashSet::new()
    }

    fn base(definition: Value) -> Value {
        json!({"id": "svc", "title": "Service", "description": "", "category": "app", "parameters": [{"key": "svc", "label": "服务", "hint": "", "required": true}], "definition": definition})
    }

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(key, value)| (key.to_string(), value.to_string())).collect()
    }

    fn task_of(commands: Vec<String>) -> Result<(), String> {
        check_as_task(TaskSpec { name: "t".into(), targets: PROBE_HOST.into(), playbook: Playbook::Custom, instruction: Some("x".into()), commands, ..Default::default() }, &none())
    }

    #[test]
    fn accepts_read_only_commands_with_placeholders_and_rejects_writing_ones() {
        let template = validate_template(&base(json!({"playbook": "custom", "instruction": "check {{svc}}", "commands": [" systemctl is-active {{svc}} ", "journalctl -u {{svc}} -n 20 --no-pager"]})), &none()).unwrap();
        assert_eq!(template.definition.commands, ["systemctl is-active {{svc}}", "journalctl -u {{svc}} -n 20 --no-pager"]);
        assert!(validate_template(&base(json!({"playbook": "inspect", "instruction": "x"})), &none()).unwrap().definition.commands.is_empty());
        let many: Vec<&str> = vec!["true"; 21];
        for commands in [vec!["systemctl restart {{svc}}"], vec!["sudo cat /etc/shadow"], vec!["ls; rm -rf /tmp/x"], vec!["cat {{missing}}"], vec![""], many] {
            assert!(validate_template(&base(json!({"playbook": "custom", "instruction": "x", "commands": commands})), &none()).is_err(), "{commands:?}");
        }
    }

    #[test]
    fn inserts_parameter_values_as_one_quoted_word_so_a_value_cannot_add_a_command() {
        let template = validate_template(&base(json!({"playbook": "custom", "instruction": "check {{svc}}", "commands": ["systemctl is-active {{svc}}"]})), &none()).unwrap();
        let hostile = "nginx'; rm -rf / #";
        let rendered = render_template_commands(&template, &values(&[("svc", hostile)]), true).unwrap().remove(0);
        assert_eq!(rendered, format!("systemctl is-active {}", shell_word(hostile)));
        assert!(rendered.contains(r"'nginx'\''; rm -rf / #'"));
        // The value is inert as a shell word, and the classifier still refuses the quoted deletion text when the task is saved.
        assert_eq!(classify_command(&rendered, &none()).level, RiskLevel::Destructive);
        assert!(task_of(vec![rendered]).unwrap_err().contains("not read-only"));
        let benign = render_template_commands(&template, &values(&[("svc", "nginx postgresql")]), true).unwrap().remove(0);
        assert_eq!(benign, "systemctl is-active 'nginx postgresql'");
        assert_eq!(classify_command(&benign, &none()).level, RiskLevel::Read);
        task_of(vec![benign]).unwrap();
        assert!(render_template_commands(&template, &BTreeMap::new(), true).unwrap_err().contains("请填写"));
        assert!(render_template_commands(&template, &BTreeMap::new(), false).unwrap()[0].contains("【待填写：服务】"));
    }

    #[test]
    fn rejects_reserved_malformed_and_host_bound_templates() {
        let good = json!({"id": "my-health", "title": "日常巡检", "description": "观察资源", "category": "自定义", "parameters": [], "definition": {"playbook": "inspect", "instruction": "只读检查资源和异常。", "schedule": {"daily": "08:30", "timeZone": "UTC"}}});
        validate_template(&good, &none()).unwrap();
        let with = |path: &str, value: Value| {
            let mut copy = good.clone();
            let mut at = &mut copy;
            let parts: Vec<&str> = path.split('.').collect();
            for part in &parts[..parts.len() - 1] { at = &mut at[*part] }
            at[parts[parts.len() - 1]] = value;
            copy
        };
        for (bad, expect) in [
            (with("id", json!("builtin.health")), "保留"),
            (with("id", json!("all")), "保留"),
            (with("id", json!("-x")), "保留"),
            (with("title", json!("  ")), "标题"),
            (with("definition.targets", json!("a")), "sudo"),
            (with("definition.sudo", json!(true)), "sudo"),
            (with("definition.instruction", json!("查 {{missing}}")), "missing"),
            (with("definition.instruction", json!(" ")), "巡查规则"),
            (with("definition.playbook", json!("new-files")), "paths"),
            (with("definition.playbook", json!("script")), "检查脚本"),
            (with("definition.schedule", json!({"daily": "08:30", "everyMinutes": 20})), "exactly one"),
            (with("definition.schedule", json!({"daily": "08:30", "timeZone": "Mars/Base"})), "时区"),
            (with("parameters", json!([{"key": "a", "label": "A", "hint": "", "required": true}, {"key": "a", "label": "B", "hint": "", "required": true}])), "重复"),
            (with("parameters", json!([{"key": "1a", "label": "A", "hint": "", "required": true}])), "参数"),
        ] {
            let error = validate_template(&bad, &none()).unwrap_err();
            assert!(error.contains(expect), "{bad} → {error}");
        }
    }

    #[test]
    fn every_builtin_is_valid_and_fills_into_a_read_only_task() {
        let all = builtin_templates(&LIMITS, "Asia/Shanghai");
        assert_eq!(all.len(), 13);
        for template in &all {
            assert!(template.builtin());
            // Validation refuses the reserved prefix, so check the body under another id.
            let mut value = serde_json::to_value(template).unwrap();
            value["id"] = json!(template.id.trim_start_matches("builtin."));
            validate_template(&value, &none()).unwrap_or_else(|error| panic!("{}: {error}", template.id));
            let given: BTreeMap<String, String> = template.parameters.iter().map(|p| (p.key.clone(), p.default_value.clone().unwrap_or_else(|| "test-target".into()))).collect();
            let (instruction, commands) = fill(template, &template.definition.instruction, &template.definition.commands, &given).unwrap();
            assert!(!instruction.contains("{{"), "{}", template.id);
            assert!(instruction.contains("只读"));
            assert!(template.definition.playbook != Playbook::Custom || !commands.is_empty(), "{} runs without the model, so it needs commands", template.id);
            for command in &commands {
                let risk = classify_command(command, &none());
                assert!(risk.level == RiskLevel::Read && !risk.elevates, "{}: {command}", template.id);
            }
        }
        assert!(all[0].definition.instruction.contains("80% 告警、90% 紧急"));
        let services = all.iter().find(|template| template.id == "builtin.services").unwrap();
        assert!(fill(services, &services.definition.instruction, &services.definition.commands, &values(&[("services", "  ")])).unwrap_err().contains("服务名称"));
        assert!(fill(services, &services.definition.instruction, &services.definition.commands, &values(&[("services", &"x".repeat(4001))])).unwrap_err().contains("格式"));
        // The person's own edit of the instruction is filled the same way.
        let (instruction, _) = fill(services, "只报告 {{services}} 的异常。", &services.definition.commands, &values(&[("services", "nginx")])).unwrap();
        assert!(instruction.starts_with("只报告 nginx 的异常。"));
    }

    #[test]
    fn drafts_are_validated_replaced_by_id_and_leave_the_queue_when_saved_or_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let template = json!({"id": "my-health", "title": "日常巡检", "description": "观察资源", "category": "自定义", "parameters": [], "definition": {"playbook": "inspect", "instruction": "只读检查资源和异常。", "schedule": {"daily": "08:30", "timeZone": "UTC"}}});
        let mut sudo = template.clone();
        sudo["definition"]["sudo"] = json!(true);
        assert!(add_template_draft(dir.path(), &sudo, &none(), 0).unwrap_err().contains("sudo"));
        let first = add_template_draft(dir.path(), &template, &none(), 0).unwrap();
        let mut other = template.clone();
        other["id"] = json!("other");
        let second = add_template_draft(dir.path(), &other, &none(), 1).unwrap();
        let mut better = template.clone();
        better["title"] = json!("改进版");
        let replaced = add_template_draft(dir.path(), &better, &none(), 2).unwrap();
        assert_ne!(first.id, replaced.id);
        let queued = draft_store(dir.path()).read().unwrap().value.entries;
        assert_eq!(queued.iter().map(|draft| (draft.template.id.as_str(), draft.template.title.as_str())).collect::<Vec<_>>(), [("other", "日常巡检"), ("my-health", "改进版")]);
        assert!(template_store(dir.path()).read().unwrap().value.entries.is_empty());
        save_template(dir.path(), &serde_json::to_value(&replaced.template).unwrap(), false, Some(&replaced.id), &none()).unwrap();
        discard_draft(dir.path(), &second.id).unwrap();
        assert!(draft_store(dir.path()).read().unwrap().value.entries.is_empty());
        let saved = template_store(dir.path()).read().unwrap().value.entries;
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].title, "改进版");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.path().join("task-templates.json")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // Only the latest few drafts are kept.
        for index in 0..12 {
            let mut many = template.clone();
            many["id"] = json!(format!("t{index}"));
            add_template_draft(dir.path(), &many, &none(), index).unwrap();
        }
        let kept = draft_store(dir.path()).read().unwrap().value.entries;
        assert_eq!(kept.len(), MAX_DRAFTS);
        assert_eq!(kept[0].template.id, "t2");
    }

    #[test]
    fn the_library_refuses_duplicates_edits_of_missing_entries_and_builtin_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let template = json!({"id": "my-health", "title": "日常巡检", "description": "", "category": "自定义", "parameters": [], "definition": {"playbook": "inspect", "instruction": "只读检查。"}});
        assert!(save_template(dir.path(), &template, true, None, &none()).unwrap_err().contains("已被删除"));
        save_template(dir.path(), &template, false, None, &none()).unwrap();
        assert!(save_template(dir.path(), &template, false, None, &none()).unwrap_err().contains("已存在"));
        let mut edited = template.clone();
        edited["definition"]["instruction"] = json!("修改后的检查。");
        save_template(dir.path(), &edited, true, None, &none()).unwrap();
        assert!(delete_template(dir.path(), "builtin.health").unwrap_err().contains("预设"));
        let all = library(dir.path(), &LIMITS, "UTC").unwrap();
        assert_eq!(all.len(), 14);
        assert_eq!(all.last().unwrap().definition.instruction, "修改后的检查。");
        delete_template(dir.path(), "my-health").unwrap();
        assert_eq!(library(dir.path(), &LIMITS, "UTC").unwrap().len(), 13);
    }
}
