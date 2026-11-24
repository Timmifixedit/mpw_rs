pub mod controls;
pub mod dialogs;
mod pages;
mod util;

use iced::{Result, Subscription, Task, Theme};

use crate::dialogs::base::{Dialog, DialogStack};
use crate::pages::login::LoginPage;
use crate::pages::page::{Page, PageResult};
use dialogs::base::DialogResult;
use iced::Element;

#[derive(Clone)]
enum Message {
    Page(pages::page::PageEvent),
    Dialog(dialogs::base::Message),
    EscapePressed,
    EnterPressed,
    CtrlCPressed,
    NoOp,
}

struct State {
    current_page: Page,
    info_dialog: DialogStack,
}

impl State {
    pub fn new() -> Self {
        let (page, error) = LoginPage::new();
        State {
            current_page: Page::Login(page),
            info_dialog: error.map_or(dialogs![], |d| d.into()),
        }
    }
}

fn view(state: &State) -> Element<'_, Message> {
    let page_view = state.current_page.view().map(Message::Page);
    iced::widget::stack![page_view, state.info_dialog.view().map(Message::Dialog)].into()
}

fn events(_: &State) -> Subscription<Message> {
    use iced::keyboard::Event as Kevt;
    use iced::keyboard::key::{Code, Key, Named, Physical};
    iced::keyboard::listen().map(|evt| match evt {
        Kevt::KeyPressed {
            key: Key::Named(Named::Escape),
            ..
        } => Message::EscapePressed,
        Kevt::KeyPressed {
            physical_key: Physical::Code(Code::KeyC),
            modifiers,
            ..
        } if modifiers.control() => Message::CtrlCPressed,
        Kevt::KeyPressed {
            key: Key::Named(Named::Enter),
            ..
        } => Message::EnterPressed,
        _ => Message::NoOp,
    })
}

fn handle_page_result(result: PageResult, state: &mut State) -> Task<Message> {
    match result {
        Ok((new_page, dialog, task)) => {
            if let Some(page) = new_page {
                state.current_page = page;
            }

            state.info_dialog = dialog;
            task.map(Message::Page)
        }
        Err(err) => {
            state.info_dialog = err.into();
            Task::none()
        }
    }
}

fn update(state: &mut State, message: Message) -> Task<Message> {
    match message {
        Message::Page(pe) => handle_page_result(state.current_page.update(pe), state),
        Message::Dialog(msg) => {
            match state.info_dialog.update(msg) {
                DialogResult::Confirmation(res) => {
                    let res = handle_page_result(state.current_page.react_to_dialog(res), state);
                    if state
                        .info_dialog
                        .next()
                        .is_some_and(|d| matches!(d, Dialog::Confirmation(_)))
                    {
                        state.info_dialog.take_next();
                    }
                    return res;
                }
                DialogResult::Message(close) => {
                    if close {
                        state.info_dialog.take_next();
                    }
                }
            }

            Task::none()
        }
        Message::EscapePressed => {
            if state.info_dialog.next().is_some() {
                state.info_dialog.take_next();
            } else {
                state.current_page.handle_escape();
            }
            Task::none()
        }
        Message::EnterPressed => {
            if state
                .info_dialog
                .next()
                .is_some_and(|d| matches!(d, Dialog::Message(_)))
            {
                state.info_dialog.take_next();
            }
            Task::none()
        }
        Message::CtrlCPressed => handle_page_result(state.current_page.handle_ctrl_c(), state),
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
