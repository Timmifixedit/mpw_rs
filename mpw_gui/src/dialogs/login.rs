use crate::controls::pw_input;
use crate::dialogs::base::make_dialog;
use iced::Element;
use iced::widget::{button, column, container, row, text};

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
}

impl LoginDialog {
    pub fn new() -> Self {
        Self {
            pw_input: pw_input::PwInput::new(),
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let pw_elem: Element<'_, pw_input::Message> = self.pw_input.view().into();
        let modal_box = container(
            column![
                text("Enter your Password").size(20),
                pw_elem.map(Message::PwMessage),
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
                self.pw_input.update(msg);
                None
            }
        }
    }
}
