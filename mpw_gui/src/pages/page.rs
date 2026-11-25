use crate::dialogs;
use crate::dialogs::base::DialogStack;
use crate::dialogs::message::MessageDialog;
use crate::pages::app_settings::AppSettingsPage;
use crate::pages::login::LoginPage;
use crate::pages::vault::VaultPage;
use crate::pages::{app_settings, login, vault};
use iced::{Element, Task};

#[macro_export]
macro_rules! no_op {
    () => {
        Ok((None, dialogs![], Task::none()))
    };
}

pub enum Page {
    Login(LoginPage),
    Vault(VaultPage),
    Settings(AppSettingsPage),
}

#[derive(Clone)]
pub enum PageEvent {
    Login(login::Message),
    Vault(vault::Message),
    Settings(app_settings::Message),
}

pub type PageMessage<M> = Result<(Option<Page>, DialogStack, Task<M>), MessageDialog>;
pub type PageResult = Result<(Option<Page>, DialogStack, Task<PageEvent>), MessageDialog>;

#[macro_export]
macro_rules! map_message {
    ($msg: expr, $target: path) => {{
        let (page, dialog, task) = $msg?;
        Ok((page, dialog, task.map($target)))
    }};
}

impl<M> From<MessageDialog> for PageMessage<M> {
    fn from(value: MessageDialog) -> Self {
        Err(value)
    }
}

impl Page {
    pub fn view(&self) -> Element<'_, PageEvent> {
        match self {
            Page::Login(page) => page.view().map(PageEvent::Login),
            Page::Vault(page) => page.view().map(PageEvent::Vault),
            Page::Settings(page) => page.view().map(PageEvent::Settings),
        }
    }

    pub fn update(&mut self, event: PageEvent) -> PageResult {
        match (self, event) {
            (Page::Login(page), PageEvent::Login(msg)) => {
                map_message!(page.update(msg), PageEvent::Login)
            }
            (Page::Vault(page), PageEvent::Vault(msg)) => {
                map_message!(page.update(msg), PageEvent::Vault)
            }
            (Page::Settings(page), PageEvent::Settings(msg)) => {
                map_message!(page.update(msg), PageEvent::Settings)
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

    pub fn handle_ctrl_c(&mut self) -> PageResult {
        match self {
            Page::Vault(page) => {
                map_message!(page.handle_ctrl_c(), PageEvent::Vault)
            }
            _ => no_op!(),
        }
    }

    pub fn react_to_dialog(&mut self, res: dialogs::confirmation::DialogResult) -> PageResult {
        match self {
            Page::Settings(page) => {
                let task = page.react_to_dialog(res).map(PageEvent::Settings);
                Ok((None, dialogs![], task))
            }
            Page::Vault(page) => {
                let task = page.react_to_dialog(res).map(PageEvent::Vault);
                Ok((None, dialogs![], task))
            }
            _ => no_op!(),
        }
    }
}
