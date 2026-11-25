use crate::controls::list_box;
use crate::controls::list_box::{ItemId, ListBox};
use crate::controls::vault_details;
use crate::controls::vault_details::VaultDetailsView;
use crate::dialogs::base::DialogStack;
use crate::dialogs::confirmation::{ConfirmationDialog, DialogResult};
use crate::dialogs::message::{MessageDialog, MessageType};
use crate::pages::login::LoginPage;
use crate::pages::page::{Page, PageMessage};
use crate::{dialogs, no_op, pages};
use iced::Element;
use iced::Task;
use iced::widget::{button, column, container, row, space, text_input};
use iced::{Alignment, Length};
use mpw_core::config::get_config_path;
use mpw_core::path_manager::PathManager;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

#[derive(Clone)]
pub enum Message {
    AddPressed,
    RemovePressed,
    SearchChanged(String),
    ListBox(list_box::Message),
    DetailView(vault_details::Message),
    SaveCompleted(Result<(), MessageDialog>),
    ClosePressed,
    Focus(pages::login::Message),
}

pub struct AppSettingsPage {
    vault_entries: Arc<RwLock<PathManager>>,
    config_file_mutex: Arc<Mutex<()>>,
    list_view: ListBox<String>,
    vault_item_detail: VaultDetailsView,
    search_string: String,
}

impl AppSettingsPage {
    pub fn new(vault_entries: PathManager) -> Self {
        let list_view = ListBox::new(vault_entries.names().map(|s| s.to_string()));
        Self {
            vault_entries: Arc::new(vault_entries.into()),
            config_file_mutex: Arc::new(().into()),
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
                            .view(Some(|name: &str| name
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
        container(column![
            container(list_column)
                .width(Length::Fill)
                .height(Length::Fill),
            container(button("Done").on_press(Message::ClosePressed)).padding(10)
        ])
        .into()
    }

    fn save_entries(&mut self) -> Task<Message> {
        let vault_entries = self.vault_entries.clone();
        let mutex = self.config_file_mutex.clone();
        Task::perform(
            async move {
                let path = get_config_path()
                    .map_err(|msg| MessageDialog::new(msg, MessageType::Error))?
                    .as_path()
                    .to_owned();
                let _guard = mutex.lock().expect("config file lock poisoned");
                vault_entries
                    .read()
                    .expect("path manager lock poisoned")
                    .save(&path)
                    .map_err(|err| MessageDialog::new(err.to_string(), MessageType::Error))
            },
            Message::SaveCompleted,
        )
    }

    pub fn update(&mut self, message: Message) -> PageMessage<Message> {
        match message {
            Message::ListBox(msg) => {
                self.list_view.update(msg);
                if let Some((_, name)) = self.list_view.selected_item() {
                    self.vault_item_detail.update_info(
                        name.clone(),
                        self.vault_entries
                            .read()
                            .expect("path manager lock poisoned")
                            .get(name)
                            .unwrap_or(Path::new(""))
                            .to_owned(),
                        self.vault_entries
                            .read()
                            .expect("path manager lock poisoned")
                            .is_default(name),
                    );
                }
            }
            Message::ClosePressed => {
                let (page, error, task) = LoginPage::new();
                return Ok((Some(Page::Login(page)), error, task.map(Message::Focus)));
            }
            Message::DetailView(msg) => {
                if self.vault_item_detail.update(msg) {
                    let (id, orig_name) = self.list_view.selected_item().expect("No selected item");
                    if orig_name == self.vault_item_detail.get_name() {
                        self.vault_entries
                            .write()
                            .expect("path manager lock poisoned")
                            .update(orig_name, self.vault_item_detail.get_path().into())?;
                        self.vault_entries
                            .write()
                            .expect("path manager lock poisoned")
                            .update_default(orig_name, self.vault_item_detail.is_default())?;
                    } else {
                        self.vault_entries
                            .write()
                            .expect("path manager lock poisoned")
                            .add(
                                self.vault_item_detail.get_name().to_string(),
                                self.vault_item_detail.get_path().into(),
                                self.vault_item_detail.is_default(),
                            )?;
                        self.vault_entries
                            .write()
                            .expect("path manager lock poisoned")
                            .remove(orig_name);
                        self.list_view
                            .update_entry(id, self.vault_item_detail.get_name().to_string());
                    }
                    return Ok((None, dialogs![], self.save_entries()));
                }
            }
            Message::SaveCompleted(res) => {
                res?;
            }
            Message::AddPressed => {
                let added = self.list_view.add_item("".into());
                self.search_string = "".into();
                self.list_view.select(added);
                self.vault_item_detail
                    .update_info("".into(), "".into(), false);
            }
            Message::RemovePressed => {
                if let Some((id, name)) = self.list_view.selected_item() {
                    return if name == "" {
                        Ok((None, dialogs![], self.remove_entry(id)))
                    } else {
                        ConfirmationDialog::new_request(
                            format!("Remove vault entry '{name}'?").into(),
                            false,
                        )
                    };
                }
            }
            Message::SearchChanged(search_string) => {
                self.search_string = search_string;
            }
            Message::Focus(_) => {}
        }
        no_op!()
    }

    pub fn handle_escape(&mut self) {
        self.list_view.unselect();
    }

    fn remove_entry(&mut self, id: ItemId) -> Task<Message> {
        let need_write = self
            .list_view
            .get_item(id)
            .is_some_and(|name| !name.is_empty());
        if let Some(name) = self.list_view.get_item(id) {
            self.vault_entries
                .write()
                .expect("path manager lock poisoned")
                .remove(name);
        }

        self.list_view.remove_entry(id);
        if need_write {
            self.save_entries()
        } else {
            Task::none()
        }
    }

    pub fn react_to_dialog(&mut self, res: DialogResult) -> Task<Message> {
        if matches!(res, DialogResult::Yes)
            && let Some((id, _)) = self.list_view.selected_item()
        {
            self.remove_entry(id)
        } else {
            Task::none()
        }
    }
}
