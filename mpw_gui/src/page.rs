use iced::Element;
use crate::login::LoginPage;
use crate::passwords::Passwords;

pub enum Page {
    Login(LoginPage),
    Vault(Passwords),
}

pub trait PageInterface {
    type Message;
    fn view(&self) -> Element<'_, Self::Message>;
    fn update(&mut self, message: Self::Message) -> Option<Page>;
}
