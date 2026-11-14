use crate::controls::pw_input;
use crate::dialogs::base::make_dialog;
use iced::widget::{button, column, container, row, space, text};
use iced::{Element, Task};
use secure_string::SecureString;

#[derive(Clone)]
pub enum Message {
    Abort,
    Confirm,
    PwMessage(pw_input::Message),
}

#[derive(Debug, Clone)]
pub enum DialogResult {
    Cancelled,
    Confirmed,
}

impl From<pw_input::Message> for Message {
    fn from(msg: pw_input::Message) -> Self {
        Message::PwMessage(msg)
    }
}

pub struct LoginDialog {
    pw_input: pw_input::PwInput,
    error: Option<String>,
}

impl LoginDialog {
    pub fn new() -> Self {
        Self {
            pw_input: pw_input::PwInput::new(),
            error: None,
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let pw_elem: Element<'_, pw_input::Message> = self.pw_input.view().into();
        let modal_box = container(
            column![
                text("Enter your Password").size(20),
                pw_elem.map(Message::PwMessage),
                if let Some(err) = &self.error {
                    container(text(err))
                } else {
                    container(space())
                },
                row![
                    button("Unlock")
                        .on_press(Message::Confirm)
                        .style(button::primary),
                    button("Abort")
                        .on_press(Message::Abort)
                        .style(button::secondary),
                ]
                .spacing(10)
            ]
            .spacing(20)
            .width(320),
        );

        make_dialog(modal_box)
    }

    pub fn update(&mut self, message: Message) -> Option<DialogResult> {
        match message {
            Message::Abort => Some(DialogResult::Cancelled),
            Message::Confirm => Some(DialogResult::Confirmed),
            Message::PwMessage(msg) => {
                self.clear_error();
                if self.pw_input.update(msg) {
                    Some(DialogResult::Confirmed)
                } else {
                    None
                }
            }
        }
    }

    pub fn get_password(&self) -> &SecureString {
        self.pw_input.password()
    }

    pub fn take_password(&mut self) -> SecureString {
        self.pw_input.take_password()
    }

    pub fn clear_password(&mut self) {
        self.pw_input.clear_password();
    }

    pub fn set_error(&mut self, err: impl ToString) {
        self.error = err.to_string().into();
    }

    pub fn clear_error(&mut self) {
        self.error = None;
    }

    pub fn focus(&mut self) -> Task<Message> {
        self.pw_input.focus().map(Message::PwMessage)
    }
}
