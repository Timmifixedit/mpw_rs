use crate::controls::pw_input;
use crate::controls::pw_input::PwInput;
use iced::widget::{button, column, container, row, space, text, text_input};
use iced::{Alignment, Element, Task};
use secure_string::SecureString;

#[derive(Clone)]
pub enum Message {
    NameChanged(String),
    LoginChanged(String),
    PwInput(pw_input::Message),
    CopyLogin,
    CopyPassword,
    SavePressed,
}

pub struct PasswordDetails {
    name: String,
    login: String,
    pw_input: PwInput,
    modified: bool,
}

impl PasswordDetails {
    pub fn new() -> Self {
        Self {
            name: "".into(),
            login: "".into(),
            pw_input: PwInput::new(),
            modified: false,
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        container(
            column![
                text("Password name").align_x(Alignment::Start),
                text_input("Enter password name", &self.name)
                    .on_input(Message::NameChanged)
                    .size(16),
                text("Login info").align_x(Alignment::Start),
                row![
                    text_input("Enter login info", &self.login)
                        .on_input(Message::LoginChanged)
                        .size(16),
                    button("Copy").on_press(Message::CopyLogin)
                ]
                .align_y(Alignment::Center)
                .spacing(10),
                text("Password").align_x(Alignment::Start),
                row![
                    self.pw_input.view().map(Message::PwInput),
                    button("Copy").on_press(Message::CopyPassword)
                ]
                .align_y(Alignment::Start)
                .spacing(10),
                if self.modified {
                    container(button("Save").on_press(Message::SavePressed))
                } else {
                    container(space())
                }
            ]
            .padding(10)
            .spacing(10),
        )
        .style(container::bordered_box)
        .into()
    }

    pub fn update(&mut self, msg: Message) -> (bool, Task<Message>) {
        match msg {
            Message::NameChanged(name) => {
                self.name = name;
                self.modified = true;
            }
            Message::LoginChanged(login) => {
                self.login = login;
                self.modified = true;
            }
            Message::PwInput(input) => {
                let pw_changed = matches!(input, pw_input::Message::PwUpdated(_));
                self.pw_input.update(input);
                if pw_changed {
                    self.modified = true;
                }
            }
            Message::SavePressed => {
                self.modified = false;
                return (true, Task::none());
            }
            Message::CopyLogin => {
                return (false, iced::clipboard::write(self.login.clone()));
            }
            Message::CopyPassword => {
                return (
                    false,
                    iced::clipboard::write(self.pw_input.password().unsecure().to_string()),
                );
            }
        }

        (false, Task::none())
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_pw(&self) -> &SecureString {
        self.pw_input.password()
    }

    pub fn get_login(&self) -> &str {
        &self.login
    }

    pub fn update_info(&mut self, name: String, pw: SecureString, login: String) {
        self.name = name;
        self.login = login;
        self.pw_input.set_password(pw);
    }
}
