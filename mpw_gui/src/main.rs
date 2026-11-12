mod login;
pub mod page;
pub mod passwords;

use iced::{Result, Theme};

use crate::login::LoginPage;
use crate::page::{Page, PageInterface};
use iced::Element;
use secure_string::SecureString;


#[derive(Debug, Clone)]
enum Message {
    Login(login::Message),
    Passwords(passwords::Message),
}

impl From<login::Message> for Message {
    fn from(value: login::Message) -> Self {
        Message::Login(value)
    }
}

impl From<passwords::Message> for Message {
    fn from(value: passwords::Message) -> Self {
        Message::Passwords(value)
    }
}

struct State {
    current_page: Page,
    master_pw: SecureString,
}

impl State {
    pub fn new() -> Self {
        State {
            current_page: Page::Login(LoginPage::new()),
            master_pw: SecureString::from(""),
        }
    }
}

fn view(state: &State) -> Element<'_, Message> {
    match &state.current_page {
        Page::Login(page) => page.view().map(Message::Login),
        Page::Vault(page) => {page.view().map(Message::Passwords)},
    }
}

macro_rules! create_dispatcher {
    ( $(($msg_variant:path, $page_variant:path)),* $(,)? ) => {
        fn update(state: &mut State, message: Message) {
            match message {
            $(
                $msg_variant(msg) => {
                    if let $page_variant(page) = &mut state.current_page {
                        if let Some(new_page) = page.update(msg) {
                            state.current_page = new_page;
                        }
                    }
                }
            )*
            }
        }
    };
}

create_dispatcher!(
    (Message::Login, Page::Login),
    (Message::Passwords, Page::Vault)
);

fn theme(state: &State) -> Theme {
    Theme::Dracula
}

fn main() -> Result {
    iced::application(State::new, update, view)
        .theme(theme)
        .run()
}
