use crate::page::Page::Vault;
use crate::page::{PageInterface, Page};
use iced::widget::{button, container, text, text_input};
use iced::{Alignment, Element, Length, alignment};
use secure_string::SecureString;
use std::path::PathBuf;
use crate::passwords::Passwords;

#[derive(Debug, Clone)]
pub enum Message {
    PwStringUpdated(String),
    LoginClicked,
}

pub struct LoginPage {
    master_pw: SecureString,
    vault_path: PathBuf,
}

impl LoginPage {
    pub fn new() -> Self {
        LoginPage {
            master_pw: "".into(),
            vault_path: "".into(),
        }
    }
}

impl PageInterface for LoginPage {
    type Message = Message;

    fn view(&self) -> Element<'_, Self::Message> {
        let content = iced::widget::column![
            text("Enter your Master Password").size(24),
            text_input("Password", self.master_pw.unsecure())
                .secure(true)
                .on_input(Message::PwStringUpdated)
                .padding(10),
            button("Login").on_press(Message::LoginClicked),
        ]
        .spacing(20)
        .align_x(Alignment::Center);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(alignment::Horizontal::Center)
            .align_y(alignment::Vertical::Center)
            .into()
    }

    fn update(&mut self, message: Self::Message) -> Option<Page> {
        match message {
            Message::PwStringUpdated(pw) => {
                self.master_pw = pw.into();
                None
            }
            Message::LoginClicked => {
                let vault = mpw_core::vault::Vault::load(self.vault_path.clone())
                    .expect("Failed to load vault");
                Vault(Passwords::new(vault)).into()
            }
        }
    }
}
