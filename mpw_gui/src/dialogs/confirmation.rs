use crate::dialogs::base::make_dialog;
use crate::pages::page::PageMessage;
use iced::widget::{button, column, container, row, space, text};
use iced::{Alignment, Element, Task};

#[derive(Debug, Clone)]
pub enum Message {
    Yes,
    No,
    Cancel,
}

pub enum DialogResult {
    Yes,
    No,
    Cancel,
}

pub struct ConfirmationDialog {
    question: String,
    has_cancel: bool,
}

impl ConfirmationDialog {
    pub fn new(question: String, has_cancel: bool) -> Self {
        Self {
            question,
            has_cancel,
        }
    }

    pub fn new_request<M>(question: String, has_cancel: bool) -> PageMessage<M> {
        Ok((
            None,
            Self::new(question, has_cancel).into(),
            Task::none(),
        ))
    }

    pub fn view(&self) -> Element<'_, Message> {
        let modal_box = container(
            column![
                text(&self.question).size(20),
                row![
                    button("Yes").on_press(Message::Yes),
                    button("No").on_press(Message::No),
                    if self.has_cancel {
                        container(button("Cancel").on_press(Message::Cancel))
                    } else {
                        container(space())
                    }
                ]
                .spacing(10)
            ]
            .spacing(10)
            .align_x(Alignment::Center),
        );
        make_dialog(modal_box)
    }

    pub fn update(&mut self, message: Message) -> DialogResult {
        match message {
            Message::Yes => DialogResult::Yes,
            Message::No => DialogResult::No,
            Message::Cancel => DialogResult::Cancel,
        }
    }
}
