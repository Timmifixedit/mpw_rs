use crate::dialogs::base;
use crate::dialogs::login::DialogResult;
use crate::dialogs::message::{MessageDialog, MessageType};
use crate::dialogs::{create_vault, login};
use crate::no_op;
use crate::pages::app_settings::AppSettingsPage;
use crate::pages::page::{Page, PageMessage};
use crate::pages::passwords::Passwords;
use iced::widget::{button, container, pick_list, stack, text};
use iced::{Alignment, Element, Font, Length, Task};
use mpw_core::config::get_config_path;
use mpw_core::path_manager::PathManager;
use mpw_core::vault::{FatalError, Vault, VaultError};
use std::path::PathBuf;

#[derive(Clone)]
enum DialogMessage {
    Login(login::Message),
    Create(create_vault::Message),
}

#[derive(Clone)]
pub enum Message {
    LoadPressed,
    SettingsPressed,
    VaultSelected(String),
    DialogMessage(DialogMessage),
}

enum Dialog {
    Login((login::LoginDialog, Vault)),
    Create((create_vault::CreateVaultDialog, PathBuf)),
    None,
}

pub struct LoginPage {
    vault_entries: PathManager,
    selected_vault: Option<String>,
    dialog: Dialog,
}

impl LoginPage {
    pub fn new() -> (Self, Option<MessageDialog>) {
        let mut message = None;
        let vault_entries = match get_config_path() {
            Ok(path) => match PathManager::load(&path) {
                Ok(pm) => pm,
                Err(e) => {
                    message = Some(MessageDialog::new(
                        format!("Could not load config file ({}): {}", path.display(), e),
                        MessageType::Warning,
                    ));
                    PathManager::default()
                }
            },
            Err(e) => {
                message = Some(MessageDialog::new(
                    format!(
                        "Could not find or create config file: '{}'. You won't be able to save your vault locations",
                        e
                    ),
                    MessageType::Error,
                ));
                PathManager::default()
            }
        };

        (
            LoginPage {
                selected_vault: vault_entries.get_default_name().map(|name| name.to_owned()),
                vault_entries,
                dialog: Dialog::None,
            },
            message,
        )
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

        let settings = button(container(text("Settings")).align_x(Alignment::Center))
            .on_press(Message::SettingsPressed)
            .width(Length::Fixed(100.0));

        let main_page = container(column![
            container(column![
                header,
                space().height(Length::FillPortion(1)),
                controls,
                space().height(Length::FillPortion(1)),
            ])
            .width(Length::Fill)
            .align_x(Alignment::Center),
            container(settings)
                .width(Length::Fill)
                .align_x(Alignment::Start),
        ])
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(10)
        .align_x(Alignment::Center);
        stack![
            main_page,
            match &self.dialog {
                Dialog::Login((d, _)) => d
                    .view()
                    .map(|msg| Message::DialogMessage(DialogMessage::Login(msg))),
                Dialog::Create((d, _)) => d
                    .view()
                    .map(|msg| Message::DialogMessage(DialogMessage::Create(msg))),
                Dialog::None => container(space()).into(),
            }
        ]
        .into()
    }

    fn handle_dialog_message(&mut self, msg: DialogMessage) -> PageMessage<Message> {
        match (msg, &mut self.dialog) {
            (DialogMessage::Login(msg), Dialog::Login((d, vault))) => {
                use mpw_core::error::MpwError::WrongPassword;
                use mpw_core::vault::VaultError::CoreError;
                match d.update(msg) {
                    DialogResult::Cancelled => {
                        self.dialog = Dialog::None;
                    }
                    DialogResult::Confirmed => {
                        let res = vault.unlock(d.take_password());
                        if res.is_err_and(|err| matches!(err, CoreError(WrongPassword))) {
                            d.set_error("Wrong password");
                            return no_op!();
                        }

                        if let Dialog::Login((_, unlocked_vault)) =
                            std::mem::replace(&mut self.dialog, Dialog::None)
                        {
                            let (page, err) = Passwords::new(unlocked_vault);
                            return Ok((
                                Page::Vault(page).into(),
                                err.map(base::Dialog::Message),
                                Task::none(),
                            ));
                        }
                    }
                    DialogResult::None => {}
                }
            }
            (DialogMessage::Create(msg), Dialog::Create((d, _))) => {
                let (res, task) = d.update(msg);
                match res {
                    DialogResult::Cancelled => {
                        self.dialog = Dialog::None;
                    }
                    DialogResult::Confirmed => {
                        if let Dialog::Create((d, vault_path)) =
                            std::mem::replace(&mut self.dialog, Dialog::None)
                        {
                            let pw = d.take_password();
                            let mut vault = Vault::new(vault_path, pw.clone())?;
                            vault.unlock(pw)?;
                            let (page, err) = Passwords::new(vault);
                            return Ok((
                                Page::Vault(page).into(),
                                err.map(base::Dialog::Message),
                                Task::none(),
                            ));
                        }
                    }
                    DialogResult::None => {}
                }

                return Ok((
                    None,
                    None,
                    task.map(|msg| Message::DialogMessage(DialogMessage::Create(msg))),
                ));
            }
            _ => {}
        }
        no_op!()
    }

    pub fn update(&mut self, message: Message) -> PageMessage<Message> {
        match message {
            Message::LoadPressed => {
                if let Some(vault_name) = self.selected_vault.as_ref() {
                    let vault_path = self.vault_entries.get(vault_name).unwrap().to_owned();
                    let vault_res = Vault::load(vault_path.clone());
                    return match vault_res {
                        Ok(vault) => {
                            let d = login::LoginDialog::new();
                            let task = d.focus();
                            self.dialog = Dialog::Login((d, vault));
                            Ok((
                                None,
                                None,
                                task.map(|msg| Message::DialogMessage(DialogMessage::Login(msg))),
                            ))
                        }
                        Err(err) => match err {
                            VaultError::Fatal(FatalError::VaultFileNotFound(_)) => {
                                let d = create_vault::CreateVaultDialog::new();
                                let task = d.focus();
                                self.dialog = Dialog::Create((d, vault_path));
                                Ok((
                                    None,
                                    None,
                                    task.map(|msg| {
                                        Message::DialogMessage(DialogMessage::Create(msg))
                                    }),
                                ))
                            }
                            _ => Err(err.into()),
                        },
                    };
                }
            }
            Message::VaultSelected(v_name) => {
                self.selected_vault = Some(v_name);
            }
            Message::DialogMessage(msg) => {
                return self.handle_dialog_message(msg);
            }

            Message::SettingsPressed => {
                return Ok((
                    Page::Settings(AppSettingsPage::new(self.vault_entries.clone())).into(),
                    None,
                    Task::none(),
                ));
            }
        }

        no_op!()
    }

    pub fn handle_escape(&mut self) {
        self.dialog = Dialog::None;
    }
}
