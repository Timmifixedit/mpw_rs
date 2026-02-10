use clap::Parser;
use image::ImageReader;
use std::path::{Path, PathBuf};
use tray_icon::{Icon, TrayIconBuilder};

const UNLOCKED: &str = "Unlocked.png";
const LOCKED: &str = "Locked.png";

#[derive(Debug, Parser)]
#[command(
    version,
    about = "MPW system tray icon",
    long_about = "Shows MPW vault status in the system tray"
)]
struct Args {
    #[arg(required = true)]
    socket: PathBuf,
    #[arg(required = true)]
    executable: PathBuf,
    #[arg(required = true)]
    logo: PathBuf,
    #[arg(short, long, default_value = "5000")]
    refresh: u64,
}

fn load_icon(path: &Path) -> Icon {
    let image = ImageReader::open(path)
        .expect("Failed to open Logo.png")
        .decode()
        .expect("Failed to decode image");
    let rgba = image.to_rgba8();
    let (width, height) = rgba.dimensions();
    Icon::from_rgba(rgba.into_raw(), width, height).unwrap()
}

struct Status {
    locked_image: Icon,
    unlocked_image: Icon,
    exec_path: PathBuf,
    socket_path: PathBuf,
}

impl Status {
    pub fn new(args: &Args) -> Self {
        Self {
            locked_image: load_icon(&args.logo.join(LOCKED)),
            unlocked_image: load_icon(&args.logo.join(UNLOCKED)),
            exec_path: args.executable.clone(),
            socket_path: args.socket.clone(),
        }
    }

    pub fn get_icon(&self) -> &Icon {
        let output = match std::process::Command::new(&self.exec_path)
            .args(&[&*self.socket_path.to_string_lossy(), "status"])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
        {
            Ok(output) => output,
            Err(err) => {
                eprintln!("Failed to run mpw_client: {}", err);
                return &self.locked_image;
            }
        };
        let result = match String::from_utf8(output.stdout) {
            Ok(result) => result,
            Err(err) => {
                eprintln!("Failed to parse output: {}", err);
                return &self.locked_image;
            }
        };

        if result.trim() == "unlocked" {
            &self.unlocked_image
        } else {
            &self.locked_image
        }
    }
}

fn main() {
    let args = Args::parse();

    // Explicitly initialize GTK. This is crucial on Linux for tray-icon.
    gtk::init().expect("Failed to initialize GTK");
    let status = Status::new(&args);

    let tray_icon = TrayIconBuilder::new()
        .with_tooltip("MPW")
        .with_icon(status.get_icon().clone())
        .build()
        .unwrap();

    glib::timeout_add_local(std::time::Duration::from_millis(args.refresh), move || {
        tray_icon.set_icon(Some(status.get_icon().clone())).unwrap();
        glib::ControlFlow::Continue
    });

    // Run the GTK main loop
    gtk::main();
}
