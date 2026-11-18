use crate::dialogs::confirmation;
use crate::dialogs::confirmation::ConfirmationDialog;
use crate::dialogs::message;
use crate::dialogs::message::MessageDialog;
use iced::widget::{Container, container, opaque, row, space};
use iced::{Color, Element, Length, alignment};
use mpw_core::vault::VaultErrorStack;

pub fn make_dialog<'a, M: 'a>(content: Container<'a, M>) -> iced::Element<'a, M> {
    opaque(
        container(content.padding(24).style(container::bordered_box))
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(alignment::Horizontal::Center)
            .align_y(alignment::Vertical::Center)
            .style(|_theme| container::Style {
                background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.7).into()),
                ..Default::default()
            }),
    )
}

pub fn make_dialog_flex<'a, M: 'a>(content: Container<'a, M>) -> iced::Element<'a, M> {
    opaque(
        container(row![
            space().width(Length::FillPortion(1)),
            content
                .padding(24)
                .style(container::bordered_box)
                .width(Length::FillPortion(2)),
            space().width(Length::FillPortion(1)),
        ])
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(alignment::Horizontal::Center)
        .align_y(alignment::Vertical::Center)
        .style(|_theme| container::Style {
            background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.7).into()),
            ..Default::default()
        }),
    )
}

pub enum Dialog {
    Message(MessageDialog),
    Confirmation(ConfirmationDialog),
}

impl From<MessageDialog> for Dialog {
    fn from(value: MessageDialog) -> Self {
        Self::Message(value)
    }
}

impl From<ConfirmationDialog> for Dialog {
    fn from(value: ConfirmationDialog) -> Self {
        Self::Confirmation(value)
    }
}

impl From<VaultErrorStack> for Dialog {
    fn from(value: VaultErrorStack) -> Self {
        Self::Message(value.into())
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    Confirmation(confirmation::Message),
    Message(message::Message),
}

pub enum DialogResult {
    Confirmation(confirmation::DialogResult),
    Message(bool),
}

impl Dialog {
    pub fn view(&self) -> Element<'_, Message> {
        match self {
            Dialog::Message(dialog) => dialog.view().map(Message::Message),
            Dialog::Confirmation(dialog) => dialog.view().map(Message::Confirmation),
        }
    }

    pub fn update(&mut self, message: Message) -> DialogResult {
        match (self, message) {
            (Dialog::Message(dialog), Message::Message(msg)) => {
                DialogResult::Message(dialog.update(msg))
            }
            (Dialog::Confirmation(dialog), Message::Confirmation(msg)) => {
                DialogResult::Confirmation(dialog.update(msg))
            }
            _ => DialogResult::Message(false),
        }
    }
}
