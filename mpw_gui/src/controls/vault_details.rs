use iced::widget::{Container, button, column, container, space, text, text_input};
use iced::{Alignment, Element};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum Message {
    SavePressed,
    PathChooserPressed,
    NameChanged(String),
    PathChanged(PathBuf),
}

pub struct VaultDetailsView {
    name: String,
    path: PathBuf,
    modified: bool,
}

impl VaultDetailsView {
    pub fn new() -> Self {
        Self {
            name: String::new(),
            path: PathBuf::new(),
            modified: false,
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        container(
            column![
                text("Vault Name").align_x(Alignment::Start),
                text_input("Enter a name", &self.name)
                    .on_input(Message::NameChanged)
                    .size(16),
                text("Path to Vault").align_x(Alignment::Start),
                text_input("Enter a path", &self.path.to_string_lossy())
                    .on_input(|val| Message::PathChanged(val.into()))
                    .size(16),
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

    pub fn update(&mut self, message: Message) -> bool {
        match message {
            Message::NameChanged(name) => {
                self.name = name;
                self.modified = true;
            }
            Message::PathChanged(path) => {
                self.path = path;
                self.modified = true;
            }
            Message::SavePressed => {
                self.modified = false;
                return true;
            }
            Message::PathChooserPressed => {}
        }

        false
    }

    pub fn update_info(&mut self, name: String, path: PathBuf) {
        self.name = name;
        self.path = path;
        self.modified = false;
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_path(&self) -> &PathBuf {
        &self.path
    }
}
