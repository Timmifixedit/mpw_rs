use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write, Read, Seek};
use secure_string::SecureVec;
use crate::error;

pub fn read_bytes(file: &mut fs::File, len: usize, offset: std::io::SeekFrom) -> Result<Vec<u8>, std::io::Error> {
    file.seek(offset)?;
    let mut ret = vec![0u8; len];
    file.read_exact(&mut ret)?;
    Ok(ret)
}

pub fn read_all(file: &str, offset: std::io::SeekFrom) -> Result<Vec<u8>, std::io::Error> {
    let mut file_handle = File::open(file).map_err(|e| std::io::Error::new(
        e.kind(),
        format!("Failed to open file: {}", e.to_string()),
    ))?;

    file_handle.seek(offset)?;
    let mut ret = Vec::<u8>::new();
    file_handle.read_to_end(&mut ret)?;
    Ok(ret)
}

pub fn transfer_data<Source: Read, Dest: Write>(source: Source, dest: &mut Dest) -> error::Result<(Source, usize)> {
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

        b_dest.write_all(&buf.unsecure()[..num_read])?;
    }

    b_dest.flush()?;
    Ok((b_source.into_inner(), num_read_total))
}
