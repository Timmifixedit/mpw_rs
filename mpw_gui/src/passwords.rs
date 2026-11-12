use crate::page::{Page, PageInterface};
use iced::widget::{container, text, button};
use iced::{Alignment, Element, Length, alignment};
use mpw_core::vault::Vault;
use crate::login::LoginPage;

#[derive(Debug, Clone)]
pub enum Message {
    Quit,
}

pub struct Passwords {
    vault: Vault,
}

impl Passwords {
    pub fn new(vault: Vault) -> Self {
        Passwords { vault }
    }
}

impl PageInterface for Passwords {
    type Message = Message;

    fn view(&self) -> Element<'_, Self::Message> {
        let content = iced::widget::column![
            text("Vault Unlocked").size(32),
            text("Your passwords are accessible here."), //.padding(10),
            button("Back to Login").on_press(Message::Quit),
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
            Message::Quit => {
                self.vault.lock().expect("error locking");
                Page::Login(LoginPage::new()).into()
            }
        }
    }
}
