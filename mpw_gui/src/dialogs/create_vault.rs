use crate::dialogs::base::make_dialog;
use crate::dialogs::login::DialogResult;
use iced::widget::{button, checkbox, column, container, row, space, text, text_input};
use iced::{Alignment, Element, Task};
use secure_string::SecureString;

#[derive(Debug, Clone)]
pub enum Message {
    Pw1Changed(SecureString),
    Pw2Changed(SecureString),
    ShowToggled(bool),
    Abort,
    Confirm,
    EnterPressed(bool),
}

pub struct CreateVaultDialog {
    pw1: SecureString,
    pw2: SecureString,
    error: Option<String>,
    show: bool,
    id1: iced::widget::Id,
    id2: iced::widget::Id,
}

impl CreateVaultDialog {
    pub fn new() -> Self {
        Self {
            pw1: "".into(),
            pw2: "".into(),
            error: None,
            show: false,
            id1: iced::widget::Id::unique(),
            id2: iced::widget::Id::unique(),
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let content = container(
            column![
                text("Create a new vault").size(20),
                column![
                    text("Password").size(16),
                    text_input("", self.pw1.unsecure())
                        .on_input(|pw| Message::Pw1Changed(pw.into()))
                        .on_submit(Message::EnterPressed(false))
                        .secure(!self.show)
                        .id(self.id1.clone())
                        .size(16),
                    text("Confirm password").size(16),
                    text_input("", self.pw2.unsecure())
                        .on_input(|pw| Message::Pw2Changed(pw.into()))
                        .on_submit(Message::EnterPressed(true))
                        .secure(!self.show)
                        .id(self.id2.clone())
                        .size(16),
                    row![
                        checkbox(self.show).on_toggle(Message::ShowToggled),
                        text("Show password")
                    ]
                    .align_y(Alignment::Center)
                    .spacing(10)
                ]
                .spacing(10)
                .align_x(Alignment::Start),
                if let Some(err) = self.error.as_ref() {
                    container(text(err))
                } else {
                    container(space())
                },
                row![
                    button("Create")
                        .on_press(Message::Confirm)
                        .style(button::primary),
                    button("Abort")
                        .on_press(Message::Abort)
                        .style(button::secondary),
                ]
                .spacing(10)
            ]
            .align_x(Alignment::Start)
            .width(320)
            .spacing(20),
        );
        make_dialog(content)
    }

    pub fn update(&mut self, msg: Message) -> (DialogResult, Task<Message>) {
        match msg {
            Message::Pw1Changed(pw) => {
                self.pw1 = pw;
                self.error = None
            }
            Message::Pw2Changed(pw) => {
                self.pw2 = pw;
                self.error = None
            }
            Message::ShowToggled(show) => self.show = show,
            Message::Abort => {
                return (DialogResult::Cancelled, Task::none());
            }
            Message::Confirm => {
                if self.pw1 == self.pw2 {
                    return (DialogResult::Confirmed, Task::none());
                }
                self.error = Some("Passwords do not match".into());
            }
            Message::EnterPressed(second_field) => {
                if second_field && self.pw1 == self.pw2 {
                    return (DialogResult::Confirmed, Task::none());
                }

                if !second_field {
                    return (
                        DialogResult::None,
                        iced::widget::operation::focus(self.id2.clone()),
                    );
                }
            }
        }
        (DialogResult::None, Task::none())
    }

    pub fn focus(&self) -> Task<Message> {
        iced::widget::operation::focus(self.id1.clone())
    }

    pub fn password(&self) -> &SecureString {
        &self.pw1
    }

    pub fn take_password(self) -> SecureString {
        self.pw1
    }
}
