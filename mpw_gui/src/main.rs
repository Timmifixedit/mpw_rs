pub mod controls;
pub mod dialogs;
mod pages;

use iced::{Result, Subscription, Task, Theme};

use crate::dialogs::message::MessageDialog;
use crate::pages::login::LoginPage;
use crate::pages::page::Page;
use iced::Element;

#[derive(Clone)]
enum Message {
    Page(pages::page::PageEvent),
    Dialog(dialogs::message::Message),
    EscapePressed,
    NoOp,
}

struct State {
    current_page: Page,
    info_dialog: Option<MessageDialog>,
}

impl State {
    pub fn new() -> Self {
        let (page, error) = LoginPage::new();
        State {
            current_page: Page::Login(page),
            info_dialog: error,
        }
    }
}

fn view(state: &State) -> Element<'_, Message> {
    let page_view = state.current_page.view().map(Message::Page);
    if let Some(dialog) = &state.info_dialog {
        iced::widget::stack![page_view, dialog.view().map(Message::Dialog)].into()
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
            Ok((new_page, dialog, task)) => {
                if let Some(page) = new_page {
                    state.current_page = page;
                }

                state.info_dialog = dialog;
                task.map(Message::Page)
            }
            Err(err) => {
                state.info_dialog = Some(err);
                Task::none()
            }
        },
        Message::Dialog(msg) => {
            if let Some(dialog) = &mut state.info_dialog
                && dialog.update(msg)
            {
                state.info_dialog = None;
            }

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
