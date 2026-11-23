use crate::dialogs::message::MessageDialog;
use crate::pages::page::PageMessage;
use crate::pages::passwords::Passwords;
use crate::pages::vault_settings::VaultSettingsPage;
use crate::pages::{passwords, vault_settings};
use crate::{dialogs, map_message, no_op};
use iced::{Element, Task};
use iced_aw::TabLabel;
use iced_aw::tabs::Tabs;
use mpw_core::vault::Vault;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tab {
    Passwords,
    Files,
    Settings,
}

#[derive(Clone)]
pub enum Message {
    PwPage(passwords::Message),
    SettingsPage(vault_settings::Message),
    TabSelected(Tab),
}

pub struct VaultPage {
    active_tab: Tab,
    pw_page: Passwords,
    settings_page: VaultSettingsPage,
    vault: Vault,
}

impl VaultPage {
    pub fn new(vault: Vault) -> (Self, Option<MessageDialog>) {
        let (pw_page, err) = Passwords::new(&vault);
        (
            Self {
                active_tab: Tab::Passwords,
                pw_page,
                settings_page: VaultSettingsPage::new(),
                vault,
            },
            err,
        )
    }

    pub fn view(&self) -> Element<'_, Message> {
        let tabs = Tabs::new(Message::TabSelected)
            .push(
                Tab::Passwords,
                TabLabel::Text("Passwords".into()),
                self.pw_page.view().map(Message::PwPage),
            )
            .push(
                Tab::Settings,
                TabLabel::Text("Settings".into()),
                self.settings_page.view().map(Message::SettingsPage),
            )
            .set_active_tab(&self.active_tab);
        tabs.into()
    }

    pub fn update(&mut self, message: Message) -> PageMessage<Message> {
        match message {
            Message::PwPage(msg) => {
                map_message!(self.pw_page.update(msg, &mut self.vault), Message::PwPage)
            }
            Message::TabSelected(tab) => {
                self.active_tab = tab;
                no_op!()
            }
            Message::SettingsPage(msg) => {
                map_message!(
                    self.settings_page.update(msg, &mut self.vault),
                    Message::SettingsPage
                )
            }
        }
    }

    pub fn handle_escape(&mut self) {
        match self.active_tab {
            Tab::Passwords => {
                self.pw_page.handle_escape();
            }
            Tab::Files => {}
            Tab::Settings => {
                self.settings_page.handle_escape();
            }
        }
    }

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
                return self.pw_page.react_to_dialog(res, &mut self.vault);
            }
            Tab::Files => {}
            Tab::Settings => {}
        }

        Ok(())
    }
}
