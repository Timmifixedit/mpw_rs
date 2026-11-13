use crate::dialogs::base::make_dialog;
use iced::widget::{Text, button, container, text};
use iced::{Element, alignment};

#[derive(Debug, Clone)]
pub enum Message {
    Ok,
}

pub enum MessageType {
    Info,
    Warning,
    Error,
}

pub struct MessageDialog {
    message: String,
    m_type: MessageType,
}

impl MessageDialog {
    pub fn new(message: impl Into<String>, m_type: MessageType) -> Self {
        Self {
            message: message.into(),
            m_type,
        }
    }

    fn header(&self) -> Text<'_> {
        match self.m_type {
            MessageType::Info => text("Info"),
            MessageType::Warning => text("Warning"),
            MessageType::Error => text("Error"),
        }
        .size(48)
    }

    pub fn view(&self) -> Element<'_, Message> {
        let modal_box = container(
            iced::widget::column![
                self.header(),
                text(&self.message).size(20),
                button("Ok")
                    .on_press(Message::Ok)
                    .style(button::primary),
            ]
            .spacing(20)
            .width(320)
            .align_x(alignment::Horizontal::Center),
        );

        make_dialog(modal_box)
    }
}
