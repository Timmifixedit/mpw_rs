use crate::controls::list_box;
use crate::controls::list_box::ListBox;
use crate::controls::vault_details;
use crate::controls::vault_details::VaultDetailsView;
use crate::no_op;
use crate::pages::page::PageMessage;
use iced::Element;
use iced::Task;
use iced::widget::{button, column, container, row, space, text_input};
use iced::{Alignment, Length};
use mpw_core::path_manager::PathManager;

#[derive(Debug, Clone)]
pub enum Message {
    AddPressed,
    RemovePressed,
    SearchChanged(String),
    ListBox(list_box::Message),
    DetailView(vault_details::Message),
    ClosePressed,
}

pub struct AppSettingsPage {
    vault_entries: PathManager,
    list_view: ListBox<String>,
    vault_item_detail: VaultDetailsView,
    search_string: String,
}

impl AppSettingsPage {
    pub fn new(vault_entries: PathManager) -> Self {
        let list_view = ListBox::new(vault_entries.names().map(|s| s.to_string()));
        Self {
            vault_entries,
            list_view,
            vault_item_detail: VaultDetailsView::new(),
            search_string: String::new(),
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let list_column = container(
            column![
                container(
                    row![
                        text_input("Search", &self.search_string)
                            .width(Length::Fixed(300.0))
                            .on_input(Message::SearchChanged),
                        button("Add").on_press(Message::AddPressed),
                        button("Remove").on_press(Message::RemovePressed)
                    ]
                    .spacing(10)
                )
                .align_x(Alignment::Start),
                row![
                    container(
                        self.list_view
                            .view(Some(|name: &String| name
                                .to_lowercase()
                                .contains(&self.search_string.to_lowercase())))
                            .map(Message::ListBox)
                    )
                    .width(Length::FillPortion(2)),
                    if self.list_view.selected_item().is_some() {
                        container(self.vault_item_detail.view().map(Message::DetailView))
                            .width(Length::FillPortion(1))
                    } else {
                        container(space()).width(Length::FillPortion(1)).into()
                    }
                ]
                .spacing(20)
                .align_y(Alignment::Start)
            ]
            .spacing(10),
        )
        .padding(10);
        container(list_column)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    pub fn update(&mut self, message: Message) -> PageMessage<Message> {
        match message {
            Message::ListBox(msg) => {
                self.list_view.update(msg);
                if let Some((_, name)) = self.list_view.selected_item() {
                    self.vault_item_detail.update_info(
                        name.clone(),
                        self.vault_entries
                            .get(name)
                            .expect("The entry should exist")
                            .to_owned(),
                    );
                }
            }
            Message::ClosePressed => {}
            Message::DetailView(msg) => {
                if self.vault_item_detail.update(msg) {
                    let (id, orig_name) = self.list_view.selected_item().expect("No selected item");
                    if orig_name == self.vault_item_detail.get_name() {
                        self.vault_entries
                            .update(orig_name, self.vault_item_detail.get_path().into())?;
                    } else {
                        self.vault_entries.add(
                            self.vault_item_detail.get_name().to_string(),
                            self.vault_item_detail.get_path().into(),
                            false,
                        )?;
                        self.vault_entries.remove(orig_name);
                        self.list_view
                            .update_entry(&id, self.vault_item_detail.get_name().to_string());
                    }
                }
            }
            Message::AddPressed => {}
            Message::RemovePressed => {
                if let Some((id, name)) = self.list_view.selected_item() {
                    self.vault_entries.remove(name);
                    self.list_view.remove_entry(&id);
                }
            }
            Message::SearchChanged(search_string) => {
                self.search_string = search_string;
            }
        }
        no_op!()
    }

    pub fn handle_escape(&mut self) {
        self.list_view.unselect();
    }
}
