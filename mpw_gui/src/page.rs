use crate::dialogs::message::MessageDialog;
use crate::login::LoginPage;
use crate::passwords::Passwords;
use iced::Task;


pub enum Page {
    Login(LoginPage),
    Vault(Passwords),
}

pub type PageMessage<M> = Result<(Option<Page>, Task<M>), MessageDialog>;

impl<M> From<MessageDialog> for PageMessage<M> {
    fn from(value: MessageDialog) -> Self {
        Err(value)
    }
}

#[macro_export]
macro_rules! no_op {
    () => {Ok((None, Task::none()))};
}