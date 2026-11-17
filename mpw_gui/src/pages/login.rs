use crate::dialogs::login;
use crate::dialogs::login::DialogResult;
use crate::dialogs::message::{MessageDialog, MessageType};
use crate::no_op;
use crate::pages::page::{Page, PageMessage};
use crate::pages::passwords::Passwords;
use iced::widget::{button, container, pick_list, stack, text};
use iced::{Alignment, Element, Font, Length, Task};
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

    pub fn view(&self) -> Element<'_, Message> {
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

    fn try_unlock_vault(&mut self) -> Result<(), mpw_core::vault::VaultError> {
        self.vault
            .as_mut()
            .expect("Invalid state. Vault should be loaded")
            .unlock(self.pw_dialog.take_password())
    }

    fn close_pw_dialog(&mut self) {
        self.pw_dialog.clear_password();
        self.pw_dialog.clear_error();
        self.show_pw_dialog = false;
    }

    fn open_pw_dialog(&mut self) -> Task<Message> {
        self.show_pw_dialog = true;
        self.pw_dialog.focus().map(Message::PwDialogMessage)
    }

    pub fn update(&mut self, message: Message) -> PageMessage<Message> {
        match message {
            Message::LoadPressed => {
                if let Some(vault_name) = self.selected_vault.as_ref() {
                    self.vault = Some(
                        mpw_core::vault::Vault::load(
                            self.vault_entries.get(vault_name).unwrap().to_owned(),
                        )
                        .map_err(|err| MessageDialog::new(err.to_string(), MessageType::Error))?,
                    );
                    return Ok((None, self.open_pw_dialog()));
                }
            }
            Message::VaultSelected(v_name) => {
                self.selected_vault = Some(v_name);
            }
            Message::PwDialogMessage(msg) => {
                use mpw_core::error::MpwError::WrongPassword;
                use mpw_core::vault::VaultError::CoreError;
                if let Some(res) = self.pw_dialog.update(msg) {
                    match res {
                        DialogResult::Cancelled => self.close_pw_dialog(),
                        DialogResult::Confirmed => {
                            let res = self.try_unlock_vault();
                            if res.is_err_and(|err| matches!(err, CoreError(WrongPassword))) {
                                self.pw_dialog.set_error("Wrong password");
                                return no_op!();
                            }

                            return Ok((
                                Page::Vault(Passwords::new(
                                    self.vault
                                        .take()
                                        .expect("Invalid state, a vault should be present"),
                                ))
                                .into(),
                                Task::none(),
                            ));
                        }
                    }
                }
            }
        }

        no_op!()
    }

    pub fn handle_escape(&mut self) {
        self.close_pw_dialog();
    }
}
