//! 设置: the model services the assistant can use, how the window looks,
//! the automatic inspection, and the skills the assistant may read.

use crate::app::{Cmd, MenuKind, Workspace};
use crate::dialogs::segmented;
use crate::i18n::t;
use crate::input::{InputEvent, TextInput};
use crate::theme::{self, Theme, text_px};
use crate::ui;
use gpui::{prelude::FluentBuilder, *};
use wisp_ops_core::ai::Protocol;
use wisp_ops_core::provider::{self, Provider};
use wisp_ops_core::settings::{Language, Settings};

/// The parts of the page, listed at its left.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Models,
    Appearance,
    /// 自动巡检 and 后台运行.
    Automation,
    /// 外部通知.
    Notify,
    /// The proxy and the device sync.
    Network,
    /// The data folder, updates and the version.
    Data,
    Skills,
}

/// Each part: what it is, its icon and its name.
const TABS: [(Tab, &str, &str); 7] = [
    (Tab::Models, "sparkle", "模型"),
    (Tab::Appearance, "palette", "外观"),
    (Tab::Automation, "history", "巡检与后台"),
    (Tab::Notify, "send", "通知"),
    (Tab::Network, "link", "网络与同步"),
    (Tab::Data, "folder-open", "数据与更新"),
    (Tab::Skills, "star", "技能"),
];

/// The width of the list of parts.
const NAV_W: f32 = 180.;

impl Tab {
    /// A part by the name a dev step gives it.
    pub fn named(name: &str) -> Tab {
        match name {
            "appearance" | "general" => Tab::Appearance,
            "automation" => Tab::Automation,
            "notify" => Tab::Notify,
            "network" => Tab::Network,
            "data" => Tab::Data,
            "skills" => Tab::Skills,
            _ => Tab::Models,
        }
    }
}

/// What the page holds besides the settings themselves: the fields of the provider on show.
pub struct SettingsView {
    pub tab: Tab,
    /// The provider on show, by its place.
    pub selected: usize,
    pub name: Entity<TextInput>,
    pub base_url: Entity<TextInput>,
    pub api_key: Entity<TextInput>,
    pub provider_proxy: Entity<TextInput>,
    pub new_model: Entity<TextInput>,
    pub proxy: Entity<TextInput>,
    pub scroll: ScrollHandle,
}

impl SettingsView {
    pub fn new(settings: &Settings, cx: &mut Context<Workspace>) -> SettingsView {
        let input = |placeholder: &'static str, cx: &mut Context<Workspace>| cx.new(|cx| TextInput::new(placeholder, cx));
        let api_key = cx.new(|cx| {
            let mut input = TextInput::new("粘贴 API Key；留空则读环境变量", cx);
            input.masked = true;
            input
        });
        let view = SettingsView { tab: Tab::Models, selected: 0, name: input("显示名称（可选）", cx), base_url: input("https://…", cx), api_key, provider_proxy: input("留空用全局代理；direct 表示不走代理", cx), new_model: input("模型名称，回车添加", cx), proxy: input("http://127.0.0.1:7890 或 socks5://…；留空读环境变量", cx), scroll: ScrollHandle::new() };
        for (field, entity) in [(Field::Name, &view.name), (Field::BaseUrl, &view.base_url), (Field::ApiKey, &view.api_key), (Field::ProviderProxy, &view.provider_proxy), (Field::NewModel, &view.new_model), (Field::Proxy, &view.proxy)] {
            cx.subscribe(entity, move |this: &mut Workspace, _, event: &InputEvent, cx| this.settings_field(field, *event, cx)).detach();
        }
        view.sync(settings, cx);
        view
    }

    /// Put the provider on show into the fields.
    pub fn sync(&self, settings: &Settings, cx: &mut App) {
        let blank = Provider::default();
        let provider = settings.providers.get(self.selected).unwrap_or(&blank);
        for (input, text) in [(&self.name, &provider.name), (&self.base_url, &provider.base_url), (&self.api_key, &provider.api_key), (&self.provider_proxy, &provider.proxy), (&self.proxy, &settings.proxy)] {
            input.update(cx, |input, cx| {
                if input.text() != text { input.set_text(text, cx) }
            });
        }
        self.new_model.update(cx, |input, cx| input.set_text("", cx));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    Name,
    BaseUrl,
    ApiKey,
    ProviderProxy,
    NewModel,
    Proxy,
}

/// An interval of the automatic inspection in words.
pub fn interval_label(minutes: u32) -> String {
    match minutes {
        0 => t("关闭").to_string(),
        m if m < 60 => tf!("每 {m} 分钟", "Every {m} min"),
        m => tf!("每 {} 小时", "Every {} h", m / 60),
    }
}

/// The automatic look for long tasks in words: an interval, or along with the automatic inspection.
pub fn long_auto_label(minutes: Option<u32>) -> String {
    match minutes {
        None => t("随机群巡检").to_string(),
        Some(minutes) => interval_label(minutes),
    }
}

impl Workspace {
    /// A field of the page was typed into: it is the setting from then on.
    fn settings_field(&mut self, field: Field, event: InputEvent, cx: &mut Context<Self>) {
        let view = &self.settings_view;
        let selected = view.selected;
        match (field, event) {
            (Field::NewModel, InputEvent::Submit) => {
                let model = view.new_model.read(cx).text().trim().to_string();
                if model.is_empty() { return }
                self.settings.add_model(selected, &model);
                view.new_model.update(cx, |input, cx| input.set_text("", cx));
            }
            (Field::NewModel, _) => return,
            (Field::Proxy, InputEvent::Changed) => {
                self.settings.proxy = view.proxy.read(cx).text().trim().to_string();
                wisp_ops_net::set_proxy(&self.settings.proxy);
            }
            (_, InputEvent::Changed) => {
                let text = match field {
                    Field::Name => view.name.read(cx).text().to_string(),
                    Field::BaseUrl => view.base_url.read(cx).text().to_string(),
                    Field::ApiKey => view.api_key.read(cx).text().to_string(),
                    _ => view.provider_proxy.read(cx).text().to_string(),
                };
                let Some(provider) = self.settings.providers.get_mut(selected) else { return };
                match field {
                    Field::Name => provider.name = text.trim().to_string(),
                    Field::BaseUrl => provider.base_url = text.trim().to_string(),
                    Field::ApiKey => provider.api_key = text.trim().to_string(),
                    _ => provider.proxy = text.trim().to_string(),
                }
            }
            _ => return,
        }
        self.save_settings(cx);
        cx.notify();
    }

    pub fn run_settings(&mut self, cmd: Cmd, window: &mut Window, cx: &mut Context<Self>) {
        match cmd {
            Cmd::SetSettingsTab(tab) => {
                self.page = crate::app::Page::Settings;
                self.settings_view.tab = tab;
                if tab == Tab::Skills { self.load_skills() }
            }
            Cmd::SetAppearance(appearance) => {
                self.settings.appearance = appearance.into();
                self.apply_appearance(window);
            }
            Cmd::SetLanguage(language) => {
                self.settings.language = language;
                crate::i18n::set_language(language);
                crate::background::set_menus(cx);
                window.refresh();
            }
            Cmd::SetFontSize(size) => {
                self.settings.font_size = wisp_ops_core::settings::font_size(size);
                self.apply_typography(window, cx);
            }
            Cmd::ToggleContrast => {
                self.settings.high_contrast = !self.settings.high_contrast;
                self.apply_appearance(window);
            }
            Cmd::ToggleKeepRunning => {
                self.settings.keep_running = !self.settings.keep_running;
                crate::background::stay_awake(self.settings.keep_running);
            }
            Cmd::Quit => return cx.quit(),
            Cmd::SetAutoInspect(minutes) => self.settings.auto_inspect_minutes = minutes,
            Cmd::SetAutoAccounts(minutes) => self.settings.auto_accounts_minutes = minutes,
            Cmd::SetAutoSecurity(minutes) => self.settings.auto_security_minutes = minutes,
            Cmd::SetAutoLong(minutes) => self.settings.auto_long_minutes = minutes,
            Cmd::SetDiskScan(minutes) => self.settings.disk_scan_minutes = minutes,
            Cmd::SetLongHours(hours) => self.settings.long_job_hours = hours,
            Cmd::PickChatModel(id) => self.settings.chat_model = id,
            Cmd::AddProvider(key) => {
                let provider = provider::preset(key).map(Provider::from_preset).unwrap_or_default();
                self.settings_view.selected = self.settings.add_provider(provider);
                self.settings_view.sync(&self.settings, cx);
            }
            Cmd::RemoveProvider(index) => {
                let name = self.settings.providers.get(index).map(|provider| provider.title()).unwrap_or_default();
                return self.confirm(t("删除模型服务"), tf!("删除「{name}」和它的模型？API Key 也会从设置里去掉。", "Remove “{name}” and its models? Its API key is removed from the settings too."), t("删除"), Cmd::RemoveProvider(index), cx);
            }
            Cmd::SelectProvider(index) => {
                self.settings_view.selected = index;
                self.settings_view.sync(&self.settings, cx);
            }
            Cmd::AddModel(index) => {
                let model = self.settings_view.new_model.read(cx).text().trim().to_string();
                if model.is_empty() { return }
                self.settings.add_model(index, &model);
                self.settings_view.new_model.update(cx, |input, cx| input.set_text("", cx));
            }
            Cmd::RemoveModel(provider, model) => self.settings.remove_model(provider, model),
            Cmd::SetEffort(provider, model, effort) => {
                if let Some(model) = self.settings.providers.get_mut(provider).and_then(|p| p.models.get_mut(model)) { model.effort = effort.into() }
            }
            Cmd::SetProtocol(provider, protocol) => {
                if let Some(provider) = self.settings.providers.get_mut(provider) { provider.protocol = protocol }
            }
            Cmd::ToggleSkill(name) => {
                match self.settings.skills_off.iter().position(|off| *off == name) {
                    Some(at) => {
                        self.settings.skills_off.remove(at);
                    }
                    None => self.settings.skills_off.push(name),
                }
            }
            _ => return,
        }
        self.save_settings(cx);
    }

    pub fn render_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let tab = self.settings_view.tab;
        let nav = div().id("settings-nav").flex().flex_col().flex_none().w(px(NAV_W)).h_full().overflow_y_scroll().px(px(8.)).py(px(10.)).gap(px(1.)).border_r_1().border_color(Theme::line()).children(TABS.iter().map(|(part, icon, label)| {
            let active = *part == tab;
            div()
                .id(SharedString::from(format!("settings-tab-{label}")))
                .flex()
                .flex_none()
                .items_center()
                .gap(px(9.))
                .h(text_px(34.))
                .px(px(10.))
                .rounded(px(7.))
                .cursor_pointer()
                .when(active, |d| d.bg(Theme::accent_soft()).font_weight(FontWeight::MEDIUM))
                .hover(|s| s.bg(Theme::hover()))
                .on_click(self.on(Cmd::SetSettingsTab(*part), cx))
                .child(ui::icon(icon, 15., if active { Theme::accent() } else { Theme::text_secondary() }))
                .child(div().flex_1().min_w_0().truncate().child(t(label).to_string()))
        }));
        let body = match tab {
            Tab::Models => self.render_models(window, cx),
            Tab::Appearance => self.render_appearance(cx),
            Tab::Automation => self.render_automation(cx),
            Tab::Notify => self.render_webhooks(cx).into_any_element(),
            Tab::Network => self.render_network(window, cx),
            Tab::Data => self.render_data(cx),
            Tab::Skills => self.render_skills(cx),
        };
        let content = div().id("settings-body").flex().flex_col().flex_1().min_w_0().h_full().overflow_y_scroll().track_scroll(&self.settings_view.scroll).child(div().flex().flex_col().w_full().max_w(px(860.)).px(px(24.)).py(px(20.)).gap(px(20.)).child(body));
        div()
            .flex()
            .flex_col()
            .size_full()
            .child(self.page_head(t("设置"), t("模型服务、外观、自动巡检、通知和技能；都只保存在这台电脑上"), vec![], cx))
            .child(div().flex().flex_1().min_h_0().child(nav).child(content))
            .into_any_element()
    }

    /// A label at the left of a setting and its control.
    fn setting_row(label: &str, control: AnyElement) -> Div {
        div().flex().items_center().gap(px(16.)).child(div().w(px(120.)).flex_none().text_color(Theme::text_secondary()).child(label.to_string())).child(control)
    }

    /// A titled block of the page.
    pub fn section(title: &str, about: &str) -> Div {
        div().flex().flex_col().gap(px(10.)).child(div().flex().flex_col().child(div().font_weight(FontWeight::MEDIUM).child(title.to_string())).when(!about.is_empty(), |d| d.child(div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_tertiary()).child(about.to_string()))))
    }

    fn render_models(&mut self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let view = &self.settings_view;
        let chosen = self.settings.chat_profile();
        let list = div().flex().flex_col().flex_none().w(px(220.)).gap(px(2.)).children(self.settings.providers.iter().enumerate().map(|(n, provider)| {
            let (top, _) = theme::provider_tile(&provider.preset);
            let ready = !provider.key().is_empty();
            div()
                .id(("provider", n))
                .flex()
                .items_center()
                .gap(px(9.))
                .h(text_px(38.))
                .px(px(8.))
                .rounded(px(8.))
                .cursor_pointer()
                .when(n == view.selected, |d| d.bg(Theme::pressed()))
                .hover(|s| s.bg(Theme::hover()))
                .on_click(self.on(Cmd::SelectProvider(n), cx))
                .child(div().flex().flex_none().items_center().justify_center().size(px(22.)).rounded(px(6.)).bg(top).child(ui::icon(&format!("provider-{}", if provider.preset.is_empty() { "custom" } else { provider.preset.as_str() }), 13., gpui::white())))
                .child(div().flex_1().min_w_0().truncate().child(provider.title()))
                .child(div().flex_none().size(px(7.)).rounded_full().bg(if ready { Theme::success() } else { Theme::line_strong() }))
        }))
        .child(ui::ghost_button("provider-add", Some("plus"), Some(t("添加服务").into())).justify_start().on_click(self.on_menu(MenuKind::AddProvider, cx)));

        let detail = match self.settings.providers.get(view.selected) {
            None => div().flex_1().child(ui::empty_state("sparkle", t("还没有模型服务"), t("添加一个：DeepSeek、Kimi、GLM、Claude、OpenAI，或任何 OpenAI 兼容的地址。"))),
            Some(provider) => {
                let n = view.selected;
                let env = provider.key_env();
                let from_env = provider.api_key.trim().is_empty() && !provider.key().is_empty();
                let protocols = segmented(
                    [(Protocol::OpenAI, "Chat Completions"), (Protocol::Anthropic, "Anthropic Messages"), (Protocol::Responses, "Responses")]
                        .into_iter()
                        .map(|(protocol, label)| (div().id(SharedString::from(format!("protocol-{label}"))).child(label).on_click(self.on(Cmd::SetProtocol(n, protocol), cx)), provider.protocol == protocol))
                        .collect(),
                );
                let models: Vec<Div> = provider.models.iter().enumerate().map(|(m, model)| {
                    let current = chosen.as_ref().is_some_and(|profile| profile.id == model.id);
                    let effort = wisp_ops_core::ai::EFFORTS.iter().find(|(key, _)| *key == model.effort).map_or("默认", |(_, label)| label);
                    div()
                        .flex()
                        .items_center()
                        .gap(px(8.))
                        .h(text_px(34.))
                        .px(px(10.))
                        .rounded(px(8.))
                        .border_1()
                        .border_color(if current { Theme::accent() } else { Theme::line() })
                        .child(div().flex_1().min_w_0().truncate().font_family(theme::MONO_FONT).text_size(text_px(12.)).child(model.model.clone()))
                        .when(current, |d| d.child(ui::chip(t("助手在用").to_string(), Theme::accent(), Theme::accent_soft())))
                        .when(!current, |d| d.child(ui::ghost_button(("model-use", m), None, Some(t("设为助手模型").into())).h(text_px(24.)).text_size(text_px(12.)).on_click(self.on(Cmd::PickChatModel(model.id.clone()), cx))))
                        .child(ui::ghost_button(("model-effort", m), None, Some(tf!("思考：{}", "Thinking: {}", t(effort)).into())).h(text_px(24.)).text_size(text_px(12.)).on_click(self.on_menu(MenuKind::Effort(n, m), cx)))
                        .child(ui::icon_action(("model-remove", m), "x", Theme::text_tertiary(), t("去掉这个模型")).on_click(self.on(Cmd::RemoveModel(n, m), cx)))
                }).collect();
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .gap(px(14.))
                    .child(div().flex().items_center().gap(px(8.)).child(div().flex_1().text_size(text_px(15.)).font_weight(FontWeight::SEMIBOLD).child(provider.title())).when_some(provider.preset(), |d, preset| d.child(ui::ghost_button("provider-console", Some("link"), Some(t("获取 API Key").into())).on_click(self.on(Cmd::OpenUrl(preset.console.to_string()), cx)))).child(ui::ghost_button("provider-remove", Some("bin"), Some(t("删除").into())).on_click(self.on(Cmd::RemoveProvider(n), cx))))
                    .child(ui::form_row(if from_env { tf!("API Key（现在用的是环境变量 {env}）", "API key (using environment variable {env})") } else { tf!("API Key（留空则读环境变量 {env}）", "API key (empty reads environment variable {env})") }, ui::field(&view.api_key, window, cx)))
                    .child(ui::form_row(t("服务地址").to_string(), ui::field(&view.base_url, window, cx)))
                    .child(ui::form_row(t("接口").to_string(), protocols))
                    .child(div().flex().gap(px(12.)).child(div().flex_1().child(ui::form_row(t("显示名称").to_string(), ui::field(&view.name, window, cx)))).child(div().flex_1().child(ui::form_row(t("这个服务的代理").to_string(), ui::field(&view.provider_proxy, window, cx)))))
                    .child(ui::form_row(t("模型").to_string(), div().flex().flex_col().gap(px(6.)).children(models).child(div().flex().gap(px(8.)).child(div().flex_1().child(ui::field(&view.new_model, window, cx))).child(ui::secondary_button("model-add", t("添加")).on_click(self.on(Cmd::AddModel(n), cx))))))
            }
        };
        div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(Self::section(t("模型服务"), t("助手用哪个模型在对话框右下角随时可换。API Key 明文保存在本机的 settings.json（仅本人可读）里，只发给它所属的服务。")))
            .child(div().flex().items_start().gap(px(24.)).child(list).child(detail))
            .into_any_element()
    }

    fn render_appearance(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let settings = &self.settings;
        let appearance = segmented(vec![
            (div().id("appearance-system").child(t("跟随系统")).on_click(self.on(Cmd::SetAppearance(""), cx)), settings.appearance.is_empty()),
            (div().id("appearance-light").child(t("浅色")).on_click(self.on(Cmd::SetAppearance("light"), cx)), settings.appearance == "light"),
            (div().id("appearance-dark").child(t("深色")).on_click(self.on(Cmd::SetAppearance("dark"), cx)), settings.appearance == "dark"),
        ])
        .w(px(300.));
        let language = segmented(vec![(div().id("language-zh").child("中文").on_click(self.on(Cmd::SetLanguage(Language::Zh), cx)), settings.language == Language::Zh), (div().id("language-en").child("English").on_click(self.on(Cmd::SetLanguage(Language::En), cx)), settings.language == Language::En)]).w(px(200.));
        let size = div()
            .flex()
            .items_center()
            .gap(px(8.))
            .child(ui::secondary_button("font-smaller", "A−").h(text_px(28.)).on_click(self.on(Cmd::SetFontSize(settings.font_size - 1.), cx)))
            .child(div().w(px(40.)).text_center().child(format!("{:.0}", settings.font_size)))
            .child(ui::secondary_button("font-larger", "A+").h(text_px(28.)).on_click(self.on(Cmd::SetFontSize(settings.font_size + 1.), cx)));
        let contrast = div().id("contrast").flex().items_center().gap(px(8.)).cursor_pointer().on_click(self.on(Cmd::ToggleContrast, cx)).child(switch(settings.high_contrast)).child(t("更强的文字和分隔线"));
        let row = Self::setting_row;
        Self::section(t("外观"), t("主题、语言和字号；改了立即生效。"))
            .child(row(t("主题"), appearance.into_any_element()))
            .child(row(t("语言"), language.into_any_element()))
            .child(row(t("字号"), size.into_any_element()))
            .child(row(t("高对比度"), contrast.into_any_element()))
            .into_any_element()
    }

    /// 自动巡检 for every page that has it, and whether the program goes on after the window closes.
    fn render_automation(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let settings = &self.settings;
        let row = Self::setting_row;
        let pick = |id: &'static str, label: String, menu: MenuKind, this: &Self, cx: &mut Context<Self>| ui::secondary_button(id, label).child(ui::icon("chevron-down", 12., Theme::text_tertiary())).on_click(this.on_menu(menu, cx)).into_any_element();
        let keep = div().id("keep-running").flex().items_center().gap(px(8.)).cursor_pointer().on_click(self.on(Cmd::ToggleKeepRunning, cx)).child(switch(settings.keep_running)).child(t("关闭窗口后继续运行"));
        let background = if cfg!(target_os = "macos") {
            Self::section(t("后台运行"), t("关闭窗口后程序留在后台，自动巡检、例行任务、定时磁盘扫描和外部通知照常进行。点 Dock 上的图标回到窗口，⌘Q 退出。")).child(keep)
        } else {
            Self::section(t("后台运行"), t("关闭按钮只把窗口最小化，自动巡检、例行任务、定时磁盘扫描和外部通知照常进行。要退出就用这里的按钮。")).child(div().flex().items_center().gap(px(16.)).child(keep).when(settings.keep_running, |d| d.child(ui::secondary_button("quit", t("退出 WispOps")).h(text_px(28.)).on_click(self.on(Cmd::Quit, cx)))))
        };
        div()
            .flex()
            .flex_col()
            .gap(px(24.))
            .child(
                Self::section(t("自动巡检"), t("程序运行时，每台服务器距上次巡检超过这个间隔就以只读方式、不使用 sudo 巡检一次并写入历史；机群总览据此显示状态和趋势。用户、长时任务和安全各有自己的间隔，做的和页面上的按钮一样：能以 root 读的服务器以 root 读取，记入审计。都不调用模型。"))
                    .child(row(t("机群总览"), pick("auto-inspect", interval_label(settings.auto_inspect_minutes), MenuKind::AutoInspect, self, cx)))
                    .child(row(t("用户"), pick("auto-accounts", interval_label(settings.auto_accounts_minutes), MenuKind::AutoAccounts, self, cx)))
                    .child(row(t("长时任务"), pick("auto-long", long_auto_label(settings.auto_long_minutes), MenuKind::AutoLong, self, cx)))
                    .child(row(t("安全"), pick("auto-security", interval_label(settings.auto_security_minutes), MenuKind::AutoSecurity, self, cx))),
            )
            .child(background)
            .into_any_element()
    }

    /// The proxy, and the device sync that goes through it.
    fn render_network(&mut self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let proxy = Self::section(t("网络"), t("模型请求、更新检查、外部通知和设备同步走的代理（发往本机的请求不走）。SSH 连接不受它影响，仍按 ~/.ssh/config。")).child(Self::setting_row(t("全局代理"), div().w(px(420.)).child(ui::field(&self.settings_view.proxy, window, cx)).into_any_element()));
        div().flex().flex_col().gap(px(24.)).child(proxy).child(self.render_sync(window, cx)).into_any_element()
    }

    /// Where the data is kept, the updates, and which version this is.
    fn render_data(&mut self, cx: &mut Context<Self>) -> AnyElement {
        div()
            .flex()
            .flex_col()
            .gap(px(24.))
            .child(
                Self::section(t("数据"), t("清单、密码库、操作审计、巡检历史和对话都在这个文件夹里。清单文件 inventory.yml 可以手写，保存后下一次操作即生效。"))
                    .child(div().flex().items_center().gap(px(10.)).child(div().flex_1().min_w_0().truncate().font_family(theme::MONO_FONT).text_size(text_px(12.)).text_color(Theme::text_secondary()).child(self.fleet.data_dir().display().to_string())).child(ui::secondary_button("reveal-data", t("打开文件夹")).h(text_px(28.)).on_click(self.on(Cmd::RevealData, cx)))),
            )
            .child(self.render_update_section(cx))
            .into_any_element()
    }

    fn render_skills(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let folder = wisp_ops_core::skill::folder(self.settings_path());
        let rows = self.skills.iter().map(|skill| {
            let on = !self.settings.skills_off.contains(&skill.name);
            div()
                .flex()
                .items_start()
                .gap(px(12.))
                .p(px(12.))
                .rounded(px(10.))
                .border_1()
                .border_color(Theme::line())
                .child(div().flex().flex_col().flex_1().min_w_0().gap(px(2.)).child(div().font_weight(FontWeight::MEDIUM).child(skill.name.clone())).child(div().text_size(text_px(12.)).line_height(text_px(18.)).text_color(Theme::text_secondary()).child(skill.description.clone())))
                .child(div().id(SharedString::from(format!("skill-{}", skill.name))).cursor_pointer().on_click(self.on(Cmd::ToggleSkill(skill.name.clone()), cx)).child(switch(on)))
        });
        Self::section(t("技能"), t("技能是一份做某类运维工作的说明（一个带 SKILL.md 的文件夹）。助手只看到名称和描述，需要时才读出全文照着做；技能只是文字，里面的东西不会被执行。"))
            .children(rows)
            .when(self.skills.is_empty(), |d| d.child(div().py(px(12.)).text_color(Theme::text_tertiary()).child(t("还没有技能。"))))
            .child(div().flex().items_center().gap(px(10.)).child(div().flex_1().min_w_0().truncate().font_family(theme::MONO_FONT).text_size(text_px(12.)).text_color(Theme::text_tertiary()).child(folder.display().to_string())).child(ui::secondary_button("skills-folder", t("打开技能文件夹")).h(text_px(28.)).on_click(cx.listener(move |_, _, _, cx| cx.open_with_system(&folder)))))
            .into_any_element()
    }
}

/// A switch, on or off.
pub fn switch(on: bool) -> Div {
    div().flex().flex_none().items_center().w(px(32.)).h(px(18.)).p(px(2.)).rounded_full().bg(if on { Theme::accent() } else { Theme::groove() }).when(on, |d| d.justify_end()).child(div().size(px(14.)).rounded_full().bg(gpui::white()).shadow(theme::shadow_card()))
}
