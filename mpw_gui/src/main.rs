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
    Page(page::PageEvent),
    Dialog,
    EscapePressed,
    NoOp,
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
    let page_view = state.current_page.view().map(Message::Page);
    if let Some(dialog) = &state.info_dialog {
        iced::widget::stack![page_view, dialog.view().map(|_| Message::Dialog)].into()
    } else {
        page_view
    }
}

fn events(_: &State) -> Subscription<Message> {
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

fn update(state: &mut State, message: Message) -> Task<Message> {
    match message {
        Message::Page(pe) => match state.current_page.update(pe) {
            Ok((new_page, task)) => {
                if let Some(page) = new_page {
                    state.current_page = page;
                }

                task.map(Message::Page)
            }
            Err(err) => {
                state.info_dialog = Some(err);
                Task::none()
            }
        },
        Message::Dialog => {
            state.info_dialog = None;
            Task::none()
        }
        Message::EscapePressed => {
            state.current_page.handle_escape();
            Task::none()
        }
        Message::NoOp => Task::none(),
    }
}

fn theme(_: &State) -> Theme {
    Theme::Dracula
}

fn main() -> Result {
    iced::application(State::new, update, view)
        .subscription(events)
        .theme(theme)
        .run()
}
