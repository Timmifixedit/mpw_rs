const APP_NAME: &str = "mpw";
const CONFIG_NAME: &str = "config.vlt";
use confy;
use std::path::PathBuf;

pub fn get_config_path() -> Result<PathBuf, String> {
    let config_path = confy::get_configuration_file_path(APP_NAME, Some(CONFIG_NAME)).map_or_else(
        |err| {
            eprintln!("Error getting config path: {}", err);
            let path = std::env::current_dir()
                .expect("Could not get current directory")
                .join(CONFIG_NAME);
            eprintln!("Using current working directory {}", path.display());
            path
        },
        |path| path.with_extension(""),
    );
    let config_dir = config_path.parent().ok_or("Invalid config path")?;
    if !config_path.exists() {
        println!("Config file {} does not exist", config_path.display());
        println!("Creating new config file");
        if !config_dir.exists() {
            std::fs::create_dir_all(config_dir).map_err(|e|e.to_string())?;
        }

        std::fs::File::create(&config_path).map_err(|e|e.to_string())?;
        println!("Config file created");
        Ok(config_path)

    } else {
        Ok(config_path)
    }
}
