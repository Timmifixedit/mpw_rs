use owo_colors::{OwoColorize, Rgb};

pub fn print_logo() {
    let logo_lines = vec![
        " ____    ____  _______  ____      ____         ______  _____     _____",
        "|_   \\  /   _||_   __ \\|_  _|    |_  _|      .' ___  ||_   _|   |_   _|",
        "  |   \\/   |    | |__) | \\ \\  /\\  / /______ / .'   \\_|  | |       | |",
        "  | |\\  /| |    |  ___/   \\ \\/  \\/ /|______|| |         | |   _   | |",
        " _| |_\\/_| |_  _| |_       \\  /\\  /         \\ `.___.'\\ _| |__/ | _| |_",
        "|_____||_____||_____|       \\/  \\/           `.____ .'|________||_____|",
    ];

    println!();

    // Create a rainbow gradient from red to violet
    let total_chars: usize = logo_lines.iter().map(|l| l.len()).sum();
    let mut char_count = 0;

    for line in logo_lines {
        let mut colored_line = String::new();
        for ch in line.chars() {
            let ratio = char_count as f32 / total_chars as f32;
            let color = rainbow_gradient(ratio);
            colored_line.push_str(&format!("{}", ch.color(Rgb(color.0, color.1, color.2))));
            char_count += 1;
        }
        println!("{}", colored_line);
    }

    println!();
}

fn rainbow_gradient(ratio: f32) -> (u8, u8, u8) {
    // Create a smooth rainbow gradient
    let hue = ratio * 360.0;
    hsv_to_rgb(hue, 1.0, 1.0)
}

fn hsv_to_rgb(h: f32, s: f32, v: f32) -> (u8, u8, u8) {
    let c = v * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = v - c;

    let (r, g, b) = if h < 60.0 {
        (c, x, 0.0)
    } else if h < 120.0 {
        (x, c, 0.0)
    } else if h < 180.0 {
        (0.0, c, x)
    } else if h < 240.0 {
        (0.0, x, c)
    } else if h < 300.0 {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };

    (
        ((r + m) * 255.0) as u8,
        ((g + m) * 255.0) as u8,
        ((b + m) * 255.0) as u8,
    )
}

