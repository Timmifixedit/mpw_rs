use iced::widget::{button, checkbox, column, container, row, space, text, text_input};
use iced::{Alignment, Element, Length};
use rfd::FileDialog;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum Message {
    SavePressed,
    PathChooserPressed,
    DefaultToggled(bool),
    NameChanged(String),
    PathChanged(PathBuf),
}

pub struct VaultDetailsView {
    name: String,
    path: PathBuf,
    is_default: bool,
    modified: bool,
}

impl VaultDetailsView {
    pub fn new() -> Self {
        Self {
            name: String::new(),
            path: PathBuf::new(),
            is_default: false,
            modified: false,
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        container(
            column![
                row![
                    text("Vault Name").align_x(Alignment::Start),
                    space().width(Length::Fill),
                    row![
                        checkbox(self.is_default).on_toggle(Message::DefaultToggled),
                        text("default"),
                    ]
                    .spacing(5)
                    .align_y(Alignment::Center)
                ],
                text_input("Enter a name", &self.name)
                    .on_input(Message::NameChanged)
                    .size(16),
                text("Path to Vault").align_x(Alignment::Start),
                row![
                    text_input("Enter a path", &self.path.to_string_lossy())
                        .on_input(|val| Message::PathChanged(val.into()))
                        .size(16),
                    button("Choose").on_press(Message::PathChooserPressed)
                ]
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
            Message::DefaultToggled(default) => {
                self.is_default = default;
                self.modified = true;
            }
            Message::PathChooserPressed => {
                if let Some(folder) = FileDialog::new()
                    .set_can_create_directories(true)
                    .pick_folder()
                {
                    self.path = folder;
                    self.modified = true;
                }
            }
        }

        false
    }

    pub fn update_info(&mut self, name: String, path: PathBuf, default: bool) {
        self.name = name;
        self.path = path;
        self.is_default = default;
        self.modified = false;
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_path(&self) -> &PathBuf {
        &self.path
    }

    pub fn is_default(&self) -> bool {
        self.is_default
    }
}
