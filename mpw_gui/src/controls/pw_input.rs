use iced::Alignment;
use iced::widget::{Container, button, container, text_input};
use secure_string::SecureString;
use std::mem;

#[derive(Clone)]
pub enum Message {
    PwUpdated(String), //TODO: dangerous since this will be potentially copied around
    Toggle,
    EnterPressed,
}

pub struct PwInput {
    password: SecureString,
    show_hide: String,
    hide: bool,
}

impl PwInput {
    pub fn new() -> Self {
        Self {
            password: "".into(),
            show_hide: String::from("Show"),
            hide: true,
        }
    }

    pub fn view(&self) -> Container<'_, Message> {
        let content = iced::widget::row![
            text_input("Enter your password", self.password.unsecure())
                .size(16)
                .secure(self.hide)
                .on_input(Message::PwUpdated)
                .on_submit(Message::EnterPressed),
            button(self.show_hide.as_ref()).on_press(Message::Toggle)
        ]
        .spacing(10)
        .align_y(Alignment::Center);
        container(content)
    }

    pub fn update(&mut self, message: Message) -> bool {
        match message {
            Message::PwUpdated(s) => self.password = s.into(),
            Message::Toggle => {
                self.hide = !self.hide;
                self.show_hide = if self.hide {
                    String::from("Show")
                } else {
                    String::from("Hide")
                };
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
}
