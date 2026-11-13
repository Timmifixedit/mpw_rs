use crate::controls::pw_input;
use iced::Element;
use iced::widget::{Container, button, column, container, opaque, row, text};
use iced::{Color, Length, alignment};

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
