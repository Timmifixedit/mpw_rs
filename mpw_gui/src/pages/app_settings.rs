use crate::controls::list_box;
use crate::controls::list_box::ListBox;
use crate::no_op;
use crate::pages::page::PageMessage;
use iced::Element;
use iced::Task;
use mpw_core::path_manager::PathManager;

#[derive(Debug, Clone)]
pub enum Message {
    ListBox(list_box::Message),
    ClosePressed,
}

pub struct AppSettingsPage {
    vault_entries: PathManager,
    list_view: ListBox<String>,
}

impl AppSettingsPage {
    pub fn new(vault_entries: PathManager) -> Self {
        let list_view = ListBox::new(vault_entries.names().map(|s| s.to_string()));
        Self {
            vault_entries,
            list_view,
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        self.list_view.view().map(Message::ListBox)
    }

    pub fn update(&mut self, message: Message) -> PageMessage<Message> {
        match message {
            Message::ListBox(msg) => {
                self.list_view.update(msg);
            }
            Message::ClosePressed => {}
        }
        no_op!()
    }

    pub fn handle_escape(&mut self) {
        self.list_view.unselect();
    }
}
