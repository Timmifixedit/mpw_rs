use crate::page::Page::Vault;
use crate::page::{Page, PageInterface};
use crate::passwords::Passwords;
use iced::widget::sensor::Key;
use iced::widget::{Container, button, container, opaque, pick_list, stack, text, text_input};
use iced::{Alignment, Color, Element, Font, Length, Theme, alignment};
use mpw_core::config::get_config_path;
use mpw_core::path_manager::PathManager;
use secure_string::SecureString;
use std::path::PathBuf;
use iced::wgpu::naga::compact::KeepUnused::No;

#[derive(Debug, Clone)]
pub enum Message {
    PwStringUpdated(String),
    LoadPressed,
    ShowHideToggle,
    UnlockClicked,
    AbortClicked,
    VaultSelected(String),
}

pub struct LoginPage {
    master_pw: SecureString,
    hide_pw: bool,
    show_hide: String,
    vault_entries: PathManager,
    selected_vault: Option<String>,
    show_pw_dialog: bool,
}

impl LoginPage {
    pub fn new() -> Self {
        let entries = get_config_path().map_or_else(
            || {
                eprintln!(
                    "Could not get config path. You won't be able to save your vault locations"
                );
                PathManager::default()
            },
            |path| {
                PathManager::load(&path).unwrap_or_else(|e| {
                    eprintln!("Could not load config file: {}", e);
                    PathManager::default()
                })
            },
        );
        LoginPage {
            master_pw: "".into(),
            selected_vault: entries.get_default_name().map(|name| name.to_owned()),
            hide_pw: true,
            show_hide: "show".into(),
            vault_entries: entries,
            show_pw_dialog: false,
        }
    }

    fn pw_input(&self) -> Container<'_, Message> {
        let content = iced::widget::row![
            text_input("Enter your password", self.master_pw.unsecure())
                .size(16)
                .secure(self.hide_pw)
                .on_input(Message::PwStringUpdated),
            button(self.show_hide.as_ref()).on_press(Message::ShowHideToggle)
        ]
        .spacing(10)
        .align_y(Alignment::Center);
        container(content)
    }

    fn pw_popup(&self) -> Element<'_, Message> {
        let modal_box = container(
            iced::widget::column![
                text("Enter your Password").size(20),
                self.pw_input(),
                iced::widget::row![
                    button("Unlock")
                        .on_press(Message::UnlockClicked)
                        .style(button::primary),
                    button("Abort")
                        .on_press(Message::AbortClicked)
                        .style(button::secondary),
                ]
                .spacing(10)
            ]
            .spacing(20)
            .width(320),
        )
        .padding(24)
        .style(container::bordered_box);

        opaque(
            container(modal_box)
                .width(Length::Fill)
                .height(Length::Fill)
                .align_x(alignment::Horizontal::Center)
                .align_y(alignment::Vertical::Center)
                .style(|_theme| container::Style {
                    background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.7).into()),
                    ..Default::default()
                }),
        )
    }
}

impl PageInterface for LoginPage {
    type Message = Message;

    fn view(&self) -> Element<'_, Self::Message> {
        use iced::widget::{column, row, space};
        let header = column![text("MyPW-GUI").size(48).font(Font::MONOSPACE),]
            .spacing(10)
            .align_x(Alignment::Center);

        let vaults = self.vault_entries.names().collect::<Vec<_>>();
        let drop_down = pick_list(vaults, self.selected_vault.as_ref(), |name| {
            Message::VaultSelected(name.to_string())
        });

        let controls = column![
            text("Select the vault you want to load"),
            row![drop_down, button("Load").on_press(Message::LoadPressed)].spacing(10),
        ]
        .spacing(15)
        .align_x(Alignment::Center);

        let main_page = container(column![
            header,
            space().height(Length::FillPortion(1)),
            controls,
            space().height(Length::FillPortion(1)),
        ])
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(20)
        .align_x(Alignment::Center);
        if self.show_pw_dialog {
            stack![main_page, self.pw_popup()].into()
        } else {
            main_page.into()
        }
    }

    fn update(&mut self, message: Self::Message) -> Option<Page> {
        match message {
            Message::PwStringUpdated(pw) => {
                self.master_pw = pw.into();
                None
            }
            Message::LoadPressed => {
                if self.selected_vault.is_none() {
                    return None;
                }
                let vault = mpw_core::vault::Vault::load(
                    self.vault_entries
                        .get(self.selected_vault.as_ref().unwrap())
                        .unwrap()
                        .to_owned(),
                )
                .expect("Failed to load vault");
                self.show_pw_dialog = true;
                None
            }
            Message::ShowHideToggle => {
                self.hide_pw = !self.hide_pw;
                self.show_hide = if self.hide_pw { "show" } else { "hide" }.into();
                None
            }
            Message::UnlockClicked => None,
            Message::AbortClicked => {
                self.show_pw_dialog = false;
                None
            },
            Message::VaultSelected(v_name) => {
                self.selected_vault = Some(v_name);
                None
            }
        }
    }
}
