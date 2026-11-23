use crate::dialogs::message::MessageDialog;
use crate::pages::page::PageMessage;
use crate::pages::passwords::Passwords;
use crate::pages::passwords;
use crate::{dialogs, map_message, no_op};
use iced::{Element, Task};
use iced_aw::TabLabel;
use iced_aw::tabs::Tabs;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tab {
    Passwords,
    Files,
    Settings,
}

#[derive(Clone)]
pub enum Message {
    PwPage(passwords::Message),
    TabSelected(Tab),
}

pub struct VaultPage {
    active_tab: Tab,
    pw_page: Passwords,
}

impl VaultPage {
    pub fn new(pw_page: Passwords) -> Self {
        Self {
            active_tab: Tab::Passwords,
            pw_page,
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let tabs = Tabs::new(Message::TabSelected)
            .push(
                Tab::Passwords,
                TabLabel::Text("Passwords".into()),
                self.pw_page.view().map(Message::PwPage),
            )
            .set_active_tab(&self.active_tab);
        tabs.into()
    }

    pub fn update(&mut self, message: Message) -> PageMessage<Message> {
        match message {
            Message::PwPage(msg) => {
                map_message!(self.pw_page.update(msg), Message::PwPage)
            }
            Message::TabSelected(tab) => {
                self.active_tab = tab;
                no_op!()
            }
        }
    }

    pub fn handle_escape(&mut self) {}

    pub fn handle_ctrl_c(&mut self) -> PageMessage<Message> {
        match self.active_tab {
            Tab::Passwords => {
                map_message!(self.pw_page.handle_ctrl_c(), Message::PwPage)
            }
            Tab::Files => {
                no_op!()
            }
            Tab::Settings => {
                no_op!()
            }
        }
    }

    pub fn react_to_dialog(
        &mut self,
        res: dialogs::confirmation::DialogResult,
    ) -> Result<(), MessageDialog> {
        match self.active_tab {
            Tab::Passwords => {
                return self.pw_page.react_to_dialog(res);
            }
            Tab::Files => {}
            Tab::Settings => {}
        }

        Ok(())
    }
}
