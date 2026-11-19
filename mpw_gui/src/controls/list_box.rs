use iced::widget::{button, column, container, scrollable};
use iced::{Element, Length, Theme};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum Message {
    ItemSelected(iced::widget::Id),
}

pub struct ListBox<T: AsRef<str>> {
    items: HashMap<iced::widget::Id, T>,
    selected: Option<iced::widget::Id>,
}

impl<T: AsRef<str>> ListBox<T> {
    pub fn new(data_source: impl IntoIterator<Item = T>) -> Self {
        let items = HashMap::from_iter(
            data_source
                .into_iter()
                .map(|item| (iced::widget::Id::unique(), item)),
        );
        Self {
            items,
            selected: None,
        }
    }

    pub fn view<F: Fn(&T) -> bool>(&self, filter: Option<F>) -> Element<'_, Message> {
        let items = column(
            self.items
                .iter()
                .filter(|(_, item)| filter.as_ref().map_or(true, |f| f(item)))
                .map(|(id, item)| {
                    let selected = self.selected.as_ref() == Some(id);
                    iced::widget::button(item.as_ref())
                        .padding(10)
                        .width(Length::Fill)
                        .on_press(Message::ItemSelected(id.clone()))
                        .style(move |theme: &Theme, status| {
                            let palette = theme.extended_palette();
                            if selected {
                                button::Style::default().with_background(palette.primary.base.color)
                            } else {
                                button::secondary(theme, status)
                            }
                        })
                        .into()
                }),
        )
        .spacing(2)
        .width(Length::Fill);
        let items = container(scrollable(items));
        items.into()
    }

    pub fn update(&mut self, message: Message) {
        match message {
            Message::ItemSelected(id) => {
                self.selected = Some(id);
            }
        }
    }

    pub fn update_entry(&mut self, id: &iced::widget::Id, item: T) {
        self.items.insert(id.clone(), item);
    }

    pub fn add_item(&mut self, item: T) {
        self.items.insert(iced::widget::Id::unique(), item);
    }

    pub fn remove_entry(&mut self, id: &iced::widget::Id) {
        self.unselect();
        self.items.remove(id);
    }

    pub fn selected_item(&self) -> Option<(iced::widget::Id, &T)> {
        self.selected.as_ref().map(|id| {
            (
                id.clone(),
                self.items.get(&id).expect("selected item should exist"),
            )
        })
    }

    pub fn unselect(&mut self) {
        self.selected = None;
    }
}
