use iced::widget::{button, column, container, scrollable};
use iced::{Element, Length, Theme};
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::AtomicUsize;

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, PartialOrd, Ord)]
pub struct ItemId(usize);

impl ItemId {
    pub fn unique() -> ItemId {
        ItemId(NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    ItemSelected(ItemId),
}

pub struct ListBox<T: AsRef<str>> {
    items: HashMap<ItemId, T>,
    display_items: BTreeSet<(String, ItemId)>,
    selected: Option<ItemId>,
}

impl<T: AsRef<str>> ListBox<T> {
    pub fn new(data_source: impl IntoIterator<Item = T>) -> Self {
        let mut ret = Self {
            items: HashMap::new(),
            display_items: BTreeSet::new(),
            selected: None,
        };
        ret.set_content(data_source);
        ret
    }

    pub fn view<F: Fn(&str) -> bool>(&self, filter: Option<F>) -> Element<'_, Message> {
        let items = column(
            self.display_items
                .iter()
                .filter(|(item, _)| filter.as_ref().map_or(true, |f| f(item)))
                .map(|(item, id)| {
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

    pub fn update_entry(&mut self, id: ItemId, item: T) {
        let name = item.as_ref().to_string();
        if let Some(old) = self.items.insert(id, item) {
            self.display_items.remove(&(old.as_ref().to_string(), id));
        }

        self.display_items.insert((name, id));
    }

    pub fn add_item(&mut self, item: T) -> ItemId {
        let new_id = ItemId::unique();
        self.update_entry(new_id, item);
        new_id
    }

    pub fn set_content(&mut self, items: impl IntoIterator<Item = T>) {
        let items = HashMap::from_iter(items.into_iter().map(|item| (ItemId::unique(), item)));
        let display_items = items
            .iter()
            .map(|(&id, item)| (item.as_ref().to_string(), id))
            .collect::<BTreeSet<_>>();
        self.items = items;
        self.display_items = display_items;
    }

    pub fn remove_entry(&mut self, id: ItemId) {
        self.unselect();
        if let Some(old) = self.items.remove(&id) {
            self.display_items.remove(&(old.as_ref().to_string(), id));
        }
    }
    
    pub fn get_item(&self, id: ItemId) -> Option<&T> {
        self.items.get(&id)
    }

    pub fn selected_item(&self) -> Option<(ItemId, &T)> {
        self.selected
            .map(|id| (id, self.items.get(&id).expect("selected item should exist")))
    }

    pub fn select(&mut self, id: ItemId) {
        self.selected = Some(id);
    }

    pub fn unselect(&mut self) {
        self.selected = None;
    }
}
