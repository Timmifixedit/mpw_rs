use crate::controls::list_box::{ItemId, ListBox};
use crate::controls::pw_details::PasswordDetails;
use crate::controls::{list_box, pw_details};
use crate::dialogs::base::DialogStack;
use crate::dialogs::confirmation::{ConfirmationDialog, DialogResult};
use crate::dialogs::message::{MessageDialog, MessageType};
use crate::pages::page::PageMessage;
use crate::util::vault_handler::VaultHandler;
use crate::{dialogs, no_op};
use iced::widget::{button, container, row, space, text_input};
use iced::{Alignment, Element, Length, Task};
use mpw_core::path_manager::Search;
use secure_string::SecureString;

#[derive(Clone)]
pub enum Message {
    AddPressed,
    RemovePressed,
    SearchChanged(String),
    ListBox(list_box::Message),
    PwInfo(pw_details::Message),
    PwRetrieved(Result<(String, SecureString, Option<String>), MessageDialog>),
    PwUpdated(Result<(ItemId, String), MessageDialog>),
    PwDeleted(Result<(), MessageDialog>),
}

#[derive(Debug, Clone)]
enum ConfirmedAction {
    Update,
    Remove,
    None,
}

pub struct Passwords {
    vault_handler: VaultHandler,
    pw_list: ListBox<String>,
    pw_info: PasswordDetails,
    search_string: String,
    confirmation_action: ConfirmedAction,
}

impl Passwords {
    pub fn new(vault_handler: VaultHandler) -> (Self, Option<MessageDialog>) {
        let (pw_list, message) =
            match vault_handler.blocking_operation(|v| v.list_passwords(Search::None)) {
                // TODO can we not block?
                Ok(pws) => (pws, None),
                Err(err) => (
                    vec![],
                    Some(MessageDialog::new(err.to_string(), MessageType::Error)),
                ),
            };
        (
            Passwords {
                vault_handler,
                pw_list: ListBox::new(pw_list),
                search_string: String::new(),
                pw_info: PasswordDetails::new(),
                confirmation_action: ConfirmedAction::None,
            },
            message,
        )
    }

    pub fn view(&self) -> Element<'_, Message> {
        let list_column = container(
            iced::widget::column![
                container(
                    row![
                        text_input("Search", &self.search_string)
                            .width(Length::Fixed(300.0))
                            .on_input(Message::SearchChanged),
                        button("Add").on_press(Message::AddPressed),
                        button("Remove").on_press(Message::RemovePressed)
                    ]
                    .spacing(10)
                )
                .align_x(Alignment::Start),
                row![
                    container(
                        self.pw_list
                            .view(Some(|name: &str| name
                                .to_lowercase()
                                .contains(&self.search_string.to_lowercase())))
                            .map(Message::ListBox)
                    )
                    .width(Length::FillPortion(2)),
                    if self.pw_list.selected_item().is_some() {
                        self.pw_info.view().map(Message::PwInfo)
                    } else {
                        container(space()).width(Length::FillPortion(1)).into()
                    }
                ]
                .spacing(20)
                .align_y(Alignment::Start)
            ]
            .spacing(10),
        )
        .padding(10);
        container(list_column)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    pub fn update(&mut self, message: Message) -> PageMessage<Message> {
        match message {
            Message::SearchChanged(search) => {
                self.search_string = search;
            }
            Message::ListBox(msg) => {
                self.pw_list.update(msg);
                if let Some((_, name)) = self.pw_list.selected_item() {
                    if name == "" {
                        self.pw_info.update_info("".into(), "".into(), "".into());
                    } else {
                        return Ok((None, dialogs![], self.spawn_retrieve_pw_task(name.clone())));
                    }
                }
            }
            Message::PwRetrieved(res) => {
                let (name, pw, login) = res?;
                self.pw_info
                    .update_info(name, pw, login.unwrap_or_default());
            }
            Message::PwInfo(msg) => {
                let (pw_updated, task) = self.pw_info.update(msg);
                let mut task = task.map(Message::PwInfo);
                let mut dialog = DialogStack::default();
                if pw_updated {
                    if let Some((_, name)) = self.pw_list.selected_item()
                        && name == ""
                    {
                        task = task.chain(self.spawn_update_pw_task());
                    } else {
                        self.confirmation_action = ConfirmedAction::Update;
                        dialog.push(
                            ConfirmationDialog::new(
                                "Please confirm that you want to update the password.".into(),
                                false,
                            )
                            .into(),
                        );
                    }
                }

                return Ok((None, dialog, task));
            }
            Message::PwUpdated(res) => {
                let (id, new_name) = res?;
                self.pw_list.update_entry(id, new_name);
            }
            Message::AddPressed => {
                let added = self.pw_list.add_item("".into());
                self.search_string = "".into();
                self.pw_list.select(added);
                self.pw_info.update_info("".into(), "".into(), "".into());
            }
            Message::RemovePressed => {
                if let Some((id, name)) = self.pw_list.selected_item() {
                    if name == "" {
                        self.pw_list.remove_entry(id);
                    } else {
                        self.confirmation_action = ConfirmedAction::Remove;
                        return ConfirmationDialog::new_request(
                            format!("Do you really want to delete the password '{name}'?"),
                            false,
                        );
                    }
                }
            }
            Message::PwDeleted(res) => {
                res?;
            }
        }
        no_op!()
    }

    fn spawn_retrieve_pw_task(&self, name: String) -> Task<Message> {
        let name_copy = name.to_string();
        self.vault_handler.run_task(
            move |v| {
                let (pw, login) = v.retrieve_password(&name_copy)?;
                Ok((name_copy, pw, login))
            },
            Some(&name),
            Message::PwRetrieved,
        )
    }

    fn spawn_update_pw_task(&self) -> Task<Message> {
        let (id, orig_name) = self.pw_list.selected_item().expect("No selected item");
        let orig_name = orig_name.to_string();
        let is_new_pw = orig_name == "";
        let new_name = self.pw_info.get_name().to_string();
        let pw = self.pw_info.get_pw().clone();
        let vault_handler = self.vault_handler.clone();
        let login = if self.pw_info.get_login().is_empty() {
            None
        } else {
            Some(self.pw_info.get_login().to_string())
        };
        Task::perform(
            async move {
                if orig_name != new_name && !is_new_pw {
                    vault_handler
                        .run_async(
                            |v| v.rename_password(&orig_name, &new_name),
                            Some(&orig_name),
                        )
                        .await?;
                }

                vault_handler
                    .run_async(
                        |v| v.write_password(&new_name, pw, login, !is_new_pw),
                        Some(&new_name),
                    )
                    .await?;
                Ok((id, new_name))
            },
            Message::PwUpdated,
        )
    }

    fn spawn_remove_pw_task(&mut self) -> Task<Message> {
        let (id, name) = self.pw_list.selected_item().expect("No selected item");
        let name_clone = name.clone();
        let task = self.vault_handler.run_task(
            move |v| v.delete_password(&name_clone).map_err(|e| e.into()),
            Some(&name),
            Message::PwDeleted,
        );
        self.pw_list.remove_entry(id);
        task
    }

    pub fn handle_escape(&mut self) {
        self.pw_list.unselect();
        self.pw_info.clear();
    }

    pub fn handle_shutdown(&mut self) {
        self.pw_list.unselect();
        self.pw_info.clear();
    }

    pub fn handle_ctrl_c(&mut self) -> PageMessage<Message> {
        use iced::clipboard;
        if self.pw_list.selected_item().is_none() {
            return no_op!();
        }

        Ok((
            None,
            dialogs![],
            clipboard::write(self.pw_info.get_pw().unsecure().to_string()).chain(
                clipboard::write_primary(self.pw_info.get_login().to_string()), // TODO Windows??
            ),
        ))
    }

    pub fn react_to_dialog(&mut self, res: DialogResult) -> Task<Message> {
        let action = self.confirmation_action.clone();
        self.confirmation_action = ConfirmedAction::None;
        if matches!(res, DialogResult::Yes) {
            match action {
                ConfirmedAction::Update => return self.spawn_update_pw_task(),
                ConfirmedAction::Remove => return self.spawn_remove_pw_task(),
                ConfirmedAction::None => {}
            }
        }

        Task::none()
    }
}
