use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write, Read, Seek};
use secure_string::SecureVec;

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

pub fn transfer_data<Source: Read, Dest: Write>(source: Source, dest: &mut Dest) -> Result<(Source, usize), String> {
    let mut b_source = BufReader::new(source);
    let mut b_dest = BufWriter::new(dest);

    let mut num_read_total = 0usize;
    let mut num_read: usize;
    let mut buf = SecureVec::new(vec![0u8; b_source.capacity()]);
    loop {
        num_read = b_source.read(&mut buf.unsecure_mut()).unwrap_or_default();
        num_read_total += num_read;
        if num_read == 0 {
            break;
        }

        if let Err(err) = b_dest.write_all(&buf.unsecure()[..num_read]) {
            return Err(format!("failed to write {num_read} bytes to destination buffer: {}", err.to_string()));
        }
    }

    b_dest.flush().map_err(|err| format!("failed to flush destination buffer: {}", err.to_string()))?;
    Ok((b_source.into_inner(), num_read_total))
}
