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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Models,
    General,
    Skills,
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
            Cmd::SetAutoInspect(minutes) => self.settings.auto_inspect_minutes = minutes,
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
        let tabs = segmented(vec![
            (div().id("settings-tab-models").child(t("模型")).on_click(self.on(Cmd::SetSettingsTab(Tab::Models), cx)), tab == Tab::Models),
            (div().id("settings-tab-general").child(t("通用")).on_click(self.on(Cmd::SetSettingsTab(Tab::General), cx)), tab == Tab::General),
            (div().id("settings-tab-skills").child(t("技能")).on_click(self.on(Cmd::SetSettingsTab(Tab::Skills), cx)), tab == Tab::Skills),
        ])
        .w(px(240.));
        let body = match tab {
            Tab::Models => self.render_models(window, cx),
            Tab::General => self.render_general(window, cx),
            Tab::Skills => self.render_skills(cx),
        };
        div()
            .flex()
            .flex_col()
            .size_full()
            .child(self.page_head(t("设置"), t("模型服务、外观和助手可以读的技能；都只保存在这台电脑上"), vec![tabs.into_any_element()], cx))
            .child(div().id("settings-body").flex().flex_col().flex_1().min_h_0().overflow_y_scroll().track_scroll(&self.settings_view.scroll).child(div().flex().flex_col().w_full().max_w(px(860.)).px(px(24.)).py(px(20.)).gap(px(20.)).child(body)))
            .into_any_element()
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

    fn render_general(&mut self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
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
        let row = |label: &str, control: AnyElement| div().flex().items_center().gap(px(16.)).child(div().w(px(120.)).flex_none().text_color(Theme::text_secondary()).child(label.to_string())).child(control);
        div()
            .flex()
            .flex_col()
            .gap(px(24.))
            .child(Self::section(t("外观"), "").child(row(t("主题"), appearance.into_any_element())).child(row(t("语言"), language.into_any_element())).child(row(t("字号"), size.into_any_element())).child(row(t("高对比度"), contrast.into_any_element())))
            .child(
                Self::section(t("自动巡检"), t("窗口开着时，每台服务器距上次巡检超过这个间隔就以只读方式、不使用 sudo 巡检一次并写入历史；机群总览据此显示状态和趋势。不调用模型。"))
                    .child(row(t("间隔"), ui::secondary_button("auto-inspect", interval_label(settings.auto_inspect_minutes)).child(ui::icon("chevron-down", 12., Theme::text_tertiary())).on_click(self.on_menu(MenuKind::AutoInspect, cx)).into_any_element())),
            )
            .child(self.render_webhooks(cx))
            .child(Self::section(t("网络"), t("模型请求走的代理。SSH 连接不受它影响，仍按 ~/.ssh/config。")).child(row(t("全局代理"), div().w(px(420.)).child(ui::field(&self.settings_view.proxy, window, cx)).into_any_element())))
            .child(self.render_sync(window, cx))
            .child(
                Self::section(t("数据"), t("清单、密码库、操作审计、巡检历史和对话都在这个文件夹里。清单文件 inventory.yml 可以手写，保存后下一次操作即生效。"))
                    .child(div().flex().items_center().gap(px(10.)).child(div().flex_1().min_w_0().truncate().font_family(theme::MONO_FONT).text_size(text_px(12.)).text_color(Theme::text_secondary()).child(self.fleet.data_dir().display().to_string())).child(ui::secondary_button("reveal-data", t("打开文件夹")).h(text_px(28.)).on_click(self.on(Cmd::RevealData, cx)))),
            )
            .child(self.render_update_section(cx))
            .child(div().text_size(text_px(12.)).text_color(Theme::text_placeholder()).child(format!("WispOps {}", env!("CARGO_PKG_VERSION"))))
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
