use crate::dialogs::create_vault::CreateVaultDialog;
use crate::dialogs::login::DialogResult;
use crate::dialogs::message::{MessageDialog, MessageType};
use crate::dialogs::{base, create_vault};
use crate::no_op;
use crate::pages::page::PageMessage;
use iced::widget::{button, column, container, stack};
use iced::{Element, Length, Task};
use mpw_core::vault::Vault;

#[derive(Debug, Clone)]
pub enum Message {
    ChangePwPressed,
    PwDialog(create_vault::Message),
}

pub struct VaultSettingsPage {
    change_pw_dialog: Option<CreateVaultDialog>,
}

impl VaultSettingsPage {
    pub fn new() -> Self {
        Self {
            change_pw_dialog: None,
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let page = container(column![
            container(
                button("Change Password")
                    .on_press(Message::ChangePwPressed)
                    .padding(10)
            )
            .style(container::bordered_box)
        ])
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(10);
        if let Some(dialog) = self.change_pw_dialog.as_ref() {
            stack![page, dialog.view().map(Message::PwDialog)].into()
        } else {
            page.into()
        }
    }

    pub fn update(&mut self, message: Message, vault: &mut Vault) -> PageMessage<Message> {
        match message {
            Message::ChangePwPressed => {
                let dialog = CreateVaultDialog::new("Change master password");
                let task = dialog.focus().map(Message::PwDialog);
                self.change_pw_dialog = dialog.into();
                Ok((None, None, task))
            }
            Message::PwDialog(msg) => {
                if let Some(dialog) = self.change_pw_dialog.as_mut() {
                    let (res, task) = dialog.update(msg);
                    match res {
                        DialogResult::Cancelled => {
                            self.change_pw_dialog = None;
                        }
                        DialogResult::Confirmed => {
                            if let Some(dialog) =
                                std::mem::replace(&mut self.change_pw_dialog, None)
                            {
                                vault.change_master_password(dialog.take_password())?;
                                return Ok((
                                    None,
                                    base::Dialog::Message(MessageDialog::new(
                                        "Password changed successfully",
                                        MessageType::Info,
                                    ))
                                    .into(),
                                    Task::none(),
                                ));
                            }
                        }
                        DialogResult::None => {}
                    }
                    Ok((None, None, task.map(Message::PwDialog)))
                } else {
                    no_op!()
                }
            }
        }
    }

    pub fn handle_escape(&mut self) {
        self.change_pw_dialog = None;
    }
}
