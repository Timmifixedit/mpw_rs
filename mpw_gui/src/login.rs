use crate::dialogs::login;
use crate::dialogs::login::DialogResult;
use crate::page::Page::Vault;
use crate::page::{Page, PageInterface};
use crate::passwords::Passwords;
use iced::widget::{button, container, pick_list, stack, text};
use iced::{Alignment, Element, Font, Length};
use mpw_core::config::get_config_path;
use mpw_core::path_manager::PathManager;

#[derive(Clone)]
pub enum Message {
    LoadPressed,
    VaultSelected(String),
    PwDialogMessage(login::Message),
}

pub struct LoginPage {
    vault_entries: PathManager,
    selected_vault: Option<String>,
    pw_dialog: login::LoginDialog,
    show_pw_dialog: bool,
    vault: Option<mpw_core::vault::Vault>,
}

impl From<login::Message> for Message {
    fn from(msg: login::Message) -> Self {
        Message::PwDialogMessage(msg)
    }
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
            selected_vault: entries.get_default_name().map(|name| name.to_owned()),
            vault_entries: entries,
            show_pw_dialog: false,
            pw_dialog: login::LoginDialog::new(),
            vault: None,
        }
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
            stack![
                main_page,
                self.pw_dialog.view().map(Message::PwDialogMessage)
            ]
            .into()
        } else {
            main_page.into()
        }
    }

    fn update(&mut self, message: Self::Message) -> Option<Page> {
        match message {
            Message::LoadPressed => {
                if self.selected_vault.is_none() {
                    return None;
                }
                self.vault = Some(
                    mpw_core::vault::Vault::load(
                        self.vault_entries
                            .get(self.selected_vault.as_ref().unwrap())
                            .unwrap()
                            .to_owned(),
                    )
                    .expect("Failed to load vault"),
                );
                self.show_pw_dialog = true;
                None
            }
            Message::VaultSelected(v_name) => {
                self.selected_vault = Some(v_name);
                None
            }
            Message::PwDialogMessage(msg) => {
                if let Some(res) = self.pw_dialog.update(msg) {
                    match res {
                        DialogResult::Cancelled => {
                            self.show_pw_dialog = false;
                        }
                        DialogResult::Confirmed => {
                            return Some(Vault(Passwords::new(self.vault.take().unwrap())));
                        }
                    }
                }
                None
            }
        }
    }
}
