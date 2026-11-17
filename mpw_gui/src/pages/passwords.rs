use crate::pages::login::LoginPage;
use crate::pages::page::{Page, PageMessage};
use iced::widget::{button, container, text};
use iced::{Alignment, Element, Length, Task, alignment};
use mpw_core::vault::Vault;

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

    pub fn view(&self) -> Element<'_, Message> {
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

    pub fn update(&mut self, message: Message) -> PageMessage<Message> {
        match message {
            Message::Quit => {
                let err = self
                    .vault
                    .lock()
                    .map_or_else(|err| Some(err.into()), |_| None);
                let (page, _) = LoginPage::new(); //TODO enable passing multiple messages?
                Ok((Some(Page::Login(page)), err, Task::none()))
            }
        }
    }

    pub fn handle_escape(&mut self) {}
}
