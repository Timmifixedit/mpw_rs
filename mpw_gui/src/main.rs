pub mod controls;
pub mod dialogs;
mod login;
pub mod page;
pub mod passwords;

use iced::{Result, Subscription, Task, Theme};

use crate::dialogs::message::MessageDialog;
use crate::login::LoginPage;
use crate::page::Page;
use iced::Element;

#[derive(Clone)]
enum Message {
    Login(login::Message),
    Passwords(passwords::Message),
    Dialog,
    EscapePressed,
    NoOp,
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
    info_dialog: Option<MessageDialog>,
}

impl State {
    pub fn new() -> Self {
        State {
            current_page: Page::Login(LoginPage::new()),
            info_dialog: None,
        }
    }
}

fn view(state: &State) -> Element<'_, Message> {
    let page = match &state.current_page {
        Page::Login(page) => page.view().map(Message::Login),
        Page::Vault(page) => page.view().map(Message::Passwords),
    };

    if let Some(dialog) = &state.info_dialog {
        iced::widget::stack![page, dialog.view().map(|_| Message::Dialog)].into()
    } else {
        page.into()
    }
}

macro_rules! create_dispatcher {
    ( $(($msg_variant:path, $page_variant:path)),* $(,)? ) => {
        fn update(state: &mut State, message: Message) -> Task<Message> {
            match message {
                Message::Dialog => {
                    state.info_dialog = None;
                }
            $(
                $msg_variant(msg) => {
                    if let $page_variant(page) = &mut state.current_page {
                        match page.update(msg) {
                            Ok((request, task)) => {
                                if let Some(new_page) = request {
                                    state.current_page = new_page;
                                }

                                return task.map($msg_variant);
                            }
                            Err(err) => {
                                state.info_dialog = Some(err);
                            }
                        }
                    }
                }
            )*
                Message::EscapePressed => {
                    match &mut state.current_page {
                        $(
                            $page_variant(page) => {
                                page.handle_escape();
                            }
                        )*
                    }
                }
                Message::NoOp => {}
            }

            Task::none()
        }
    };
}

fn events(state: &State) -> Subscription<Message> {
    use iced::keyboard::Event as Kevt;
    use iced::keyboard::key::Key;
    use iced::keyboard::key::Named;
    iced::keyboard::listen().map(|evt| match evt {
        Kevt::KeyPressed {
            key: Key::Named(Named::Escape),
            ..
        } => Message::EscapePressed,
        _ => Message::NoOp,
    })
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
        .subscription(events)
        .theme(theme)
        .run()
}
