use crate::controls::list_box::ListBox;
use crate::controls::pw_details::PasswordDetails;
use crate::controls::{list_box, pw_details};
use crate::dialogs::confirmation::{ConfirmationDialog, DialogResult};
use crate::dialogs::message::{MessageDialog, MessageType};
use crate::no_op;
use crate::pages::page::PageMessage;
use iced::widget::{button, container, row, space, text_input};
use iced::{Alignment, Element, Length, Task};
use mpw_core::path_manager::Search;
use mpw_core::vault::Vault;

#[derive(Clone)]
pub enum Message {
    AddPressed,
    RemovePressed,
    SearchChanged(String),
    ListBox(list_box::Message),
    PwInfo(pw_details::Message),
}

#[derive(Debug, Clone)]
enum ConfirmedAction {
    Update,
    Remove,
    None,
}

pub struct Passwords {
    vault: Vault,
    pw_list: ListBox<String>,
    pw_info: PasswordDetails,
    search_string: String,
    confirmation_action: ConfirmedAction,
}

impl Passwords {
    pub fn new(vault: Vault) -> (Self, Option<MessageDialog>) {
        let (pw_list, message) = match vault.list_passwords(Search::None) {
            Ok(pws) => (pws, None),
            Err(err) => (
                vec![],
                Some(MessageDialog::new(err.to_string(), MessageType::Error)),
            ),
        };
        (
            Passwords {
                vault,
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
                        let (pw, login) = self.vault.retrieve_password(name)?;
                        self.pw_info
                            .update_info(name.clone(), pw, login.unwrap_or_default());
                    }
                }
            }
            Message::PwInfo(msg) => {
                if self.pw_info.update(msg) {
                    if let Some((_, name)) = self.pw_list.selected_item()
                        && name == ""
                    {
                        self.update_pw()?;
                    } else {
                        self.confirmation_action = ConfirmedAction::Update;
                        return ConfirmationDialog::new_request(
                            "Please confirm that you want to update the password.".into(),
                            false,
                        );
                    }
                }
            }
            Message::AddPressed => {
                self.pw_list.add_item("".into());
                self.search_string = "".into();
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
        }
        no_op!()
    }

    fn update_pw(&mut self) -> Result<(), MessageDialog> {
        let (id, orig_name) = self.pw_list.selected_item().expect("No selected item");
        let is_new_pw = orig_name == "";
        let new_name = self.pw_info.get_name();
        if orig_name != new_name && !is_new_pw {
            self.vault.rename_password(orig_name, new_name)?;
        }

        let login = if self.pw_info.get_login() == "" {
            None
        } else {
            Some(self.pw_info.get_login().to_string())
        };
        self.vault
            .write_password(new_name, self.pw_info.get_pw().clone(), login, !is_new_pw)?;

        if orig_name != new_name {
            self.pw_list.update_entry(id, new_name.to_string());
        }

        Ok(())
    }

    fn remove_pw(&mut self) -> Result<(), MessageDialog> {
        let (id, name) = self.pw_list.selected_item().expect("No selected item");
        self.vault.delete_password(name)?;
        self.pw_list.remove_entry(id);
        Ok(())
    }

    pub fn handle_escape(&mut self) {}

    pub fn react_to_dialog(&mut self, res: DialogResult) -> Result<(), MessageDialog> {
        let action = self.confirmation_action.clone();
        self.confirmation_action = ConfirmedAction::None;
        if matches!(res, DialogResult::Yes) {
            match action {
                ConfirmedAction::Update => return self.update_pw(),
                ConfirmedAction::Remove => return self.remove_pw(),
                ConfirmedAction::None => {}
            }
        }

        Ok(())
    }
}
