use crate::error;
use secure_string::SecureVec;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, Write};
use std::path::Path;

/// Reads the exact number of specified bytes from the given offset from a stream.
/// # Parameters
/// * `data`: source data stream
/// * `len`: number of bytes to read
/// * `offset`: offset from which to start reading
/// # Returns
/// Vector containing the read bytes
/// # Errors
/// IO errors while reading from the stream
pub fn read_bytes<T: Read + Seek>(
    data: &mut T,
    len: usize,
    offset: std::io::SeekFrom,
) -> Result<Vec<u8>, std::io::Error> {
    data.seek(offset)?;
    let mut ret = vec![0u8; len];
    data.read_exact(&mut ret)?;
    Ok(ret)
}

/// Reads the contents of a file from the given offset.
/// # Parameters
/// * `file`: path to the file to read
/// * `offset`: offset from which to start reading
/// # Returns
/// Vector containing the read bytes
/// # Errors
/// IO errors while reading from the file
/// # Example
pub fn read_all(file: &Path, offset: std::io::SeekFrom) -> Result<Vec<u8>, std::io::Error> {
    let mut file_handle = File::open(file).map_err(|e| {
        std::io::Error::new(e.kind(), format!("Failed to open file: {}", e.to_string()))
    })?;

    file_handle.seek(offset)?;
    let mut ret = Vec::<u8>::new();
    file_handle.read_to_end(&mut ret)?;
    Ok(ret)
}

/// Transfers data from a source to a destination.
/// # Parameters
/// * `source`: source data stream
/// * `dest`: destination data stream
/// # Returns
/// Tuple containing the source data stream and the number of bytes transferred.
/// # Errors
/// IO errors while reading from the source or writing to the destination
/// # Example
pub fn transfer_data<Source: Read, Dest: Write>(
    source: Source,
    dest: &mut Dest,
) -> error::Result<(Source, usize)> {
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

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;
    use tempfile::NamedTempFile;

    fn setup() -> Result<NamedTempFile, std::io::Error> {
        let mut tmp_file = NamedTempFile::new()?;
        let data: Vec<u8> = (0u8..100).collect();
        tmp_file.write_all(&data)?;
        Ok(tmp_file)
    }

    #[test]
    fn test_read_bytes() -> Result<(), std::io::Error> {
        let data = setup()?;
        let mut file = File::open(data.path())?;
        let res = read_bytes(&mut file, 4, std::io::SeekFrom::Start(4))?;
        assert_eq!(res, (4u8..8).collect::<Vec<u8>>());
        Ok(())
    }

    #[test]
    fn test_read_all() -> Result<(), std::io::Error> {
        let data = setup()?;
        let result = read_all(data.path(), std::io::SeekFrom::Start(17))?;
        assert_eq!(result, (17u8..100).collect::<Vec<u8>>());
        Ok(())
    }

    #[test]
    fn test_transfer_data() {
        let data = vec![17u8; 100];
        let src = Cursor::new(&data);
        let mut dest = Vec::new();
        let (src, num_read) = transfer_data(src, &mut dest).unwrap();
        assert_eq!(num_read, 100);
        assert_eq!(src.into_inner(), &data);
        assert_eq!(dest, data);
    }
}
