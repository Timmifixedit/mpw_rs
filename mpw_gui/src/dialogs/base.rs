use iced::widget::{Container, container, opaque, row, space};
use iced::{Color, Length, alignment};

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
