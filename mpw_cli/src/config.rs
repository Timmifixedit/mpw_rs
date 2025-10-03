const APP_NAME: &str = "mpw";
const CONFIG_NAME: &str = "config.vlt";
use confy;
use std::path::PathBuf;

pub fn get_config_path() -> Option<PathBuf> {
    let config_path = confy::get_configuration_file_path(APP_NAME, Some(CONFIG_NAME))
        .map_or_else(|err| {
            eprintln!("Error getting config path: {}", err);
            let path = std::env::current_dir()
                .expect("Could not get current directory")
                .join(CONFIG_NAME);
            eprintln!("Using current working directory {}", path.display());
            path
        }, |path| path.with_extension(""));
    if !config_path.exists() {
        println!("Config file {} does not exist", config_path.display());
        println!("Creating new config file");
        std::fs::File::create(&config_path).map_or_else(
            |e| {
                eprintln!("Error creating config file: {}", e);
                None
            },
            |_| {
                println!("Config file created");
                Some(config_path)
            },
        )
    } else {
        Some(config_path)
    }
}
