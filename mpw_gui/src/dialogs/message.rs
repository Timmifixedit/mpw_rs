use crate::dialogs::base::make_dialog_flex;
use iced::Length::Fixed;
use iced::widget::{Text, button, container, text, text_editor};
use iced::{Element, Length, alignment};
use mpw_core::vault::{EncryptionNoOp, VaultError, VaultErrorStack};

#[derive(Debug, Clone)]
pub enum Message {
    Ok,
    EditorAction(text_editor::Action),
}

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd)]
pub enum MessageType {
    Info,
    Warning,
    Error,
}

impl MessageType {
    pub fn aggregate(&mut self, other: Self) {
        if *self < other {
            *self = other;
        }
    }
}

pub struct MessageDialog {
    content: text_editor::Content,
    m_type: MessageType,
}

impl From<VaultErrorStack> for MessageDialog {
    fn from(value: VaultErrorStack) -> Self {
        use VaultError::*;
        let mut message = String::new();
        let mut m_type = MessageType::Info;
        value
            .errors
            .iter()
            .map(|err| match err {
                ItemSkipped(e) => match e {
                    EncryptionNoOp::NotEncrypted(_) | EncryptionNoOp::AlreadyEncrypted(_) => {
                        (err, MessageType::Info)
                    }
                    EncryptionNoOp::VaultItem { .. } => (err, MessageType::Warning),
                    EncryptionNoOp::ProtectedItem(_) => (err, MessageType::Warning),
                },
                _ => (err, MessageType::Error),
            })
            .for_each(|(err, m)| {
                message.push_str(&format!("{}\n", err));
                m_type.aggregate(m);
            });

        MessageDialog::new(message, m_type)
    }
}

impl MessageDialog {
    pub fn new(message: impl AsRef<str>, m_type: MessageType) -> Self {
        Self {
            content: text_editor::Content::with_text(message.as_ref()),
            m_type,
        }
    }

    fn header(&self) -> Text<'_> {
        match self.m_type {
            MessageType::Info => text("Info"),
            MessageType::Warning => text("Warning"),
            MessageType::Error => text("Error"),
        }
        .size(48)
    }

    pub fn view(&self) -> Element<'_, Message> {
        let modal_box = container(
            iced::widget::column![
                self.header(),
                text_editor(&self.content)
                    .on_action(Message::EditorAction)
                    .height(Fixed(200.0))
                    .size(20)
                    .height(Fixed(200.0)),
                button("Ok").on_press(Message::Ok).style(button::primary),
            ]
            .spacing(20)
            .width(Length::FillPortion(1))
            .align_x(alignment::Horizontal::Center),
        );

        make_dialog_flex(modal_box)
    }

    pub fn update(&mut self, message: Message) -> bool {
        match message {
            Message::Ok => true, // Indicates the dialog should close
            Message::EditorAction(action) => {
                // Allow selection, scrolling, click, drag, and copy, but disallow edits
                if !action.is_edit() {
                    self.content.perform(action);
                }
                false
            }
        }
    }
}
