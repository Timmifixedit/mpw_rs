use crate::dialogs::message::MessageDialog;
use crate::login::LoginPage;
use crate::passwords::Passwords;


pub enum Page {
    Login(LoginPage),
    Vault(Passwords),
}

pub type PageRequest = Result<Option<Page>, MessageDialog>;

impl From<Page> for PageRequest {
    fn from(value: Page) -> Self {
        Ok(Some(value))
    }
}

impl From<MessageDialog> for PageRequest {
    fn from(value: MessageDialog) -> Self {
        Err(value)
    }
}

#[macro_export]
macro_rules! no_page {
    () => {Ok(None)};
}