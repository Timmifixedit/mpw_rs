use crate::page::Page::Vault;
use crate::page::{Page, PageInterface};
use crate::passwords::Passwords;
use iced::widget::{Container, button, container, text, text_input};
use iced::{Alignment, Element, Length, alignment};
use secure_string::SecureString;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum Message {
    PwStringUpdated(String),
    LoginClicked,
    ShowHideToggle,
}

pub struct LoginPage {
    master_pw: SecureString,
    vault_path: PathBuf,
    hide_pw: bool,
    show_hide: String,
}

impl LoginPage {
    pub fn new() -> Self {
        LoginPage {
            master_pw: "".into(),
            vault_path: "".into(),
            hide_pw: true,
            show_hide: "show".into(),
        }
    }

    fn pw_input(&self) -> Container<'_, Message> {
        let content = iced::widget::row![
            text_input("Password", self.master_pw.unsecure())
                .size(24)
                .secure(self.hide_pw)
                .on_input(Message::PwStringUpdated),
            button(self.show_hide.as_ref()).on_press(Message::ShowHideToggle)
        ]
        .spacing(20)
        .align_y(Alignment::Center);
        container(content)
    }
}

impl PageInterface for LoginPage {
    type Message = Message;

    fn view(&self) -> Element<'_, Self::Message> {
        let content = iced::widget::column![
            text("Enter your Master Password").size(24),
            self.pw_input().padding(20),
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
            Message::ShowHideToggle => {
                self.hide_pw = !self.hide_pw;
                self.show_hide = if self.hide_pw { "show" } else { "hide" }.into();
                None
            }
        }
    }
}
