use crate::dialogs::message::MessageDialog;
use crate::pages::{app_settings, login, passwords};
use crate::pages::login::LoginPage;
use crate::pages::passwords::Passwords;
use crate::pages::app_settings::AppSettingsPage;
use iced::{Element, Task};
use crate::dialogs;
use crate::dialogs::base::Dialog;

#[macro_export]
macro_rules! no_op {
    () => {
        Ok((None, None, Task::none()))
    };
}

pub enum Page {
    Login(LoginPage),
    Vault(Passwords),
    Settings(AppSettingsPage),
}

#[derive(Clone)]
pub enum PageEvent {
    Login(login::Message),
    Passwords(passwords::Message),
    Settings(app_settings::Message),
}

pub type PageMessage<M> = Result<(Option<Page>, Option<Dialog>, Task<M>), MessageDialog>;
type PageResult = Result<(Option<Page>, Option<Dialog>, Task<PageEvent>), MessageDialog>;

impl<M> From<MessageDialog> for PageMessage<M> {
    fn from(value: MessageDialog) -> Self {
        Err(value)
    }
}

impl Page {
    pub fn view(&self) -> Element<'_, PageEvent> {
        match self {
            Page::Login(page) => page.view().map(PageEvent::Login),
            Page::Vault(page) => page.view().map(PageEvent::Passwords),
            Page::Settings(page) => page.view().map(PageEvent::Settings),
        }
    }

    pub fn update(&mut self, event: PageEvent) -> PageResult {
        match (self, event) {
            (Page::Login(page), PageEvent::Login(msg)) => {
                let (next_page, msg, task) = page.update(msg)?;
                Ok((next_page, msg, task.map(PageEvent::Login)))
            }
            (Page::Vault(page), PageEvent::Passwords(msg)) => {
                let (next_page, msg, task) = page.update(msg)?;
                Ok((next_page, msg, task.map(PageEvent::Passwords)))
            }
            (Page::Settings(page), PageEvent::Settings(msg)) => {
                let (next_page, msg, task) = page.update(msg)?;
                Ok((next_page, msg, task.map(PageEvent::Settings)))
            }

            _ => no_op!(),
        }
    }

    pub fn handle_escape(&mut self) {
        match self {
            Page::Login(page) => page.handle_escape(),
            Page::Vault(page) => page.handle_escape(),
            Page::Settings(page) => page.handle_escape(),
        }
    }

    pub fn react_to_dialog(&mut self, res: dialogs::confirmation::DialogResult) {
        match self {
            Page::Settings(page) => page.react_to_dialog(res),
            _ => {}
        }
    }
}
