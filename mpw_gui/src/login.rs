use crate::page::Page::Vault;
use crate::page::{Page, PageInterface};
use crate::passwords::Passwords;
use iced::widget::{Container, button, container, opaque, stack, text, text_input};
use iced::{Alignment, Color, Element, Length, alignment};
use secure_string::SecureString;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum Message {
    PwStringUpdated(String),
    LoginClicked,
    ShowHideToggle,
    UnlockClicked,
    AbortClicked,
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
            text_input("Enter your password", self.master_pw.unsecure())
                .size(16)
                .secure(self.hide_pw)
                .on_input(Message::PwStringUpdated),
            button(self.show_hide.as_ref()).on_press(Message::ShowHideToggle)
        ]
        .spacing(10)
        .align_y(Alignment::Center);
        container(content)
    }

    fn pw_popup(&self) -> Element<'_, Message> {
        let modal_box = container(
            iced::widget::column![
                text("Enter your Password").size(20),
                self.pw_input(),
                iced::widget::row![
                    button("Unlock")
                        .on_press(Message::UnlockClicked)
                        .style(button::primary),
                    button("Abort")
                        .on_press(Message::AbortClicked)
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
}

impl PageInterface for LoginPage {
    type Message = Message;

    fn view(&self) -> Element<'_, Self::Message> {
        let content = iced::widget::column![
            text("MyPW-GUI").size(48),
            text("Enter your Master Password").size(24),
            self.pw_input().padding(20),
            button("Login").on_press(Message::LoginClicked),
        ]
        .spacing(20)
        .align_x(Alignment::Center);

        let main_content = container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(alignment::Horizontal::Center)
            .align_y(alignment::Vertical::Center);

        stack![main_content, self.pw_popup()].into()
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
            Message::UnlockClicked => None,
            Message::AbortClicked => None,
        }
    }
}
