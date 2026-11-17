use crate::dialogs::message::MessageDialog;
use crate::pages::login;
use crate::pages::login::LoginPage;
use crate::pages::passwords;
use crate::pages::passwords::Passwords;
use iced::{Element, Task};

#[macro_export]
macro_rules! no_op {
    () => {
        Ok((None, Task::none()))
    };
}

pub enum Page {
    Login(LoginPage),
    Vault(Passwords),
}

#[derive(Clone)]
pub enum PageEvent {
    Login(login::Message),
    Passwords(passwords::Message),
}

pub type PageMessage<M> = Result<(Option<Page>, Task<M>), MessageDialog>;
type PageResult = Result<(Option<Page>, Task<PageEvent>), MessageDialog>;

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
        }
    }

    pub fn update(&mut self, event: PageEvent) -> PageResult {
        match (self, event) {
            (Page::Login(page), PageEvent::Login(msg)) => {
                let (next_page, task) = page.update(msg)?;
                Ok((next_page, task.map(PageEvent::Login)))
            }
            (Page::Vault(page), PageEvent::Passwords(msg)) => {
                let (next_page, task) = page.update(msg)?;
                Ok((next_page, task.map(PageEvent::Passwords)))
            }

            _ => no_op!(),
        }
    }

    pub fn handle_escape(&mut self) {
        match self {
            Page::Login(page) => page.handle_escape(),
            Page::Vault(page) => page.handle_escape(),
        }
    }
}
