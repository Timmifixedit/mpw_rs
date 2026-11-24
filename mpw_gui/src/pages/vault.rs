use crate::dialogs::base::DialogStack;
use crate::dialogs::message::{MessageDialog, MessageType};
use crate::pages::login::LoginPage;
use crate::pages::page::{Page, PageMessage};
use crate::pages::passwords::Passwords;
use crate::pages::vault_settings::VaultSettingsPage;
use crate::pages::{passwords, vault_settings};
use crate::util::vault_handler::VaultHandler;
use crate::{dialogs, map_message, no_op};
use iced::widget::{button, column, container, opaque, space, stack};
use iced::{Color, Element, Length, Task};
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
    LockPressed,
    LockingFinished(Result<(), MessageDialog>),
    LockMessageDialog(dialogs::message::Message),
}

pub struct VaultPage {
    active_tab: Tab,
    pw_page: Passwords,
    settings_page: VaultSettingsPage,
    vault_handler: VaultHandler,
    shutting_down: bool,
    shutdown_message: Option<MessageDialog>,
}

impl VaultPage {
    pub fn new(vault: Vault) -> (Self, Option<MessageDialog>) {
        let vault_handler = VaultHandler::new(vault);
        let (pw_page, err) = Passwords::new(vault_handler.clone());
        (
            Self {
                active_tab: Tab::Passwords,
                pw_page,
                settings_page: VaultSettingsPage::new(vault_handler.clone()),
                vault_handler,
                shutting_down: false,
                shutdown_message: None,
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

        let glass_pane = opaque(
            container(space())
                .width(Length::Fill)
                .height(Length::Fill)
                .style(|_| container::Style {
                    background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.7).into()),
                    ..Default::default()
                }),
        );

        container(column![
            stack![
                container(tabs).width(Length::Fill).height(Length::Fill),
                if let Some(msg) = self.shutdown_message.as_ref() {
                    msg.view().map(Message::LockMessageDialog)
                } else if self.shutting_down {
                    glass_pane
                } else {
                    space().into()
                }
            ],
            container(button("Lock the vault").on_press(Message::LockPressed)).padding(10)
        ])
        .into()
    }

    fn back_to_login(&self) -> PageMessage<Message> {
        let (page, err) = LoginPage::new();
        Ok((
            Some(Page::Login(page)),
            err.map_or(dialogs![], |e| e.into()),
            Task::none(),
        ))
    }

    pub fn update(&mut self, message: Message) -> PageMessage<Message> {
        if self.shutting_down
            && !matches!(
                message,
                Message::LockingFinished(_) | Message::LockMessageDialog(_)
            )
        {
            return no_op!();
        }

        match message {
            Message::PwPage(msg) => {
                map_message!(self.pw_page.update(msg), Message::PwPage)
            }
            Message::TabSelected(tab) => {
                self.active_tab = tab;
                no_op!()
            }
            Message::SettingsPage(msg) => {
                map_message!(self.settings_page.update(msg), Message::SettingsPage)
            }
            Message::LockPressed => {
                let lock_task = self
                    .vault_handler
                    .run_task_mut(|v| v.lock().map_err(|e| e.into()), Message::LockingFinished);
                self.shutting_down = true;
                self.pw_page.handle_shutdown();
                Ok((
                    None,
                    MessageDialog::new(
                        "Vault is shutting down. Please wait while files are encrypted",
                        MessageType::Info,
                    )
                    .into(),
                    lock_task,
                ))
            }
            Message::LockingFinished(res) => {
                if let Err(lock_err) = res {
                    self.shutdown_message = Some(lock_err);
                    return no_op!();
                }

                self.back_to_login()
            }
            Message::LockMessageDialog(msg) => {
                if self
                    .shutdown_message
                    .as_mut()
                    .is_some_and(|d| d.update(msg))
                {
                    self.back_to_login()
                } else {
                    no_op!()
                }
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
                return self.pw_page.react_to_dialog(res);
            }
            Tab::Files => {}
            Tab::Settings => {}
        }

        Ok(())
    }
}
