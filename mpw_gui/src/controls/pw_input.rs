use iced::widget::{Id, checkbox, container, text, text_input};
use iced::{Alignment, Element};
use secure_string::SecureString;
use std::mem;

#[derive(Clone)]
pub enum Message {
    PwUpdated(SecureString),
    Toggle(bool),
    EnterPressed,
}

pub struct PwInput {
    password: SecureString,
    show: bool,
    text_field_id: Id,
}

impl PwInput {
    pub fn new() -> Self {
        Self {
            password: "".into(),
            show: false,
            text_field_id: Id::unique(),
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let content = iced::widget::column![
            text_input("Enter your password", self.password.unsecure())
                .size(16)
                .id(self.text_field_id.clone())
                .secure(!self.show)
                .on_input(|s| Message::PwUpdated(s.into()))
                .on_submit(Message::EnterPressed),
            iced::widget::row![
                checkbox(self.show).on_toggle(Message::Toggle),
                text("Show password")
            ]
            .align_y(Alignment::Center)
            .spacing(10)
        ]
        .spacing(10);
        container(content).into()
    }

    pub fn update(&mut self, message: Message) -> bool {
        match message {
            Message::PwUpdated(s) => self.password = s,
            Message::Toggle(visible) => {
                self.show = visible;
            }
            Message::EnterPressed => {
                return true;
            }
        }
        false
    }

    pub fn password(&self) -> &SecureString {
        &self.password
    }

    pub fn take_password(&mut self) -> SecureString {
        mem::replace(&mut self.password, "".into())
    }

    pub fn clear_password(&mut self) {
        self.password = "".into();
    }

    pub fn focus(&mut self) -> iced::Task<Message> {
        iced::widget::operation::focus(self.text_field_id.clone())
    }

    pub fn set_password(&mut self, password: SecureString) {
        self.password = password;
    }
}
