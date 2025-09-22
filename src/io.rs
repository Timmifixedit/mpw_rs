use std::fs;
use std::fs::File;
use std::io::{Read, Seek};



pub fn read_bytes(file: &mut fs::File, len: usize, offset: std::io::SeekFrom, msg: &str) -> Result<Vec<u8>, String> {
    if let Err(err) = file.seek(offset) {
        return Err(format!("Could not seek specified offset: {err}"));
    }

    let mut ret = vec![0u8; len];
    if let Err(err) = file.read_exact(&mut ret) {
        return Err(format!("Could not read {len} bytes for {msg}: {}", err.to_string()));
    }

    Ok(ret)
}

pub fn read_all(file: &String, offset: std::io::SeekFrom) -> Result<Vec<u8>, String> {
    let mut file_handle = match File::open(file) {
        Ok(file) => file,
        Err(msg) => {return Err(format!("Failed to open file {file}: {}", msg.to_string()))}
    };

    if let Err(err) = file_handle.seek(offset) {
        return Err(format!("Could not seek specified offset: {err}"));
    }

    let mut ret = Vec::<u8>::new();
    match file_handle.read_to_end(&mut ret) {
        Ok(_) => Ok(ret),
        Err(msg) => Err(format!("Failed reading file contents: {}", msg.to_string()))
    }
}
