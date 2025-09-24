use crate::error;
use secure_string::SecureVec;
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, Write};
use std::path::Path;

pub fn read_bytes(
    file: &mut fs::File,
    len: usize,
    offset: std::io::SeekFrom,
) -> Result<Vec<u8>, std::io::Error> {
    file.seek(offset)?;
    let mut ret = vec![0u8; len];
    file.read_exact(&mut ret)?;
    Ok(ret)
}

pub fn read_all(file: &Path, offset: std::io::SeekFrom) -> Result<Vec<u8>, std::io::Error> {
    let mut file_handle = File::open(file).map_err(|e| {
        std::io::Error::new(e.kind(), format!("Failed to open file: {}", e.to_string()))
    })?;

    file_handle.seek(offset)?;
    let mut ret = Vec::<u8>::new();
    file_handle.read_to_end(&mut ret)?;
    Ok(ret)
}

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
    use std::path::Path;
    use tempfile::NamedTempFile;

    struct TestFile {
        tmp_file: NamedTempFile,
        gt_data: Vec<u8>,
    }

    fn setup() -> Result<TestFile, std::io::Error> {
        let tmp_file = NamedTempFile::new()?;
        let mut file = File::create(tmp_file.path())?;
        let gt_data: Vec<u8> = (0u8..100).collect();
        file.write_all(&gt_data)?;
        Ok(TestFile { tmp_file, gt_data })
    }

    #[test]
    fn test_read_bytes() -> Result<(), std::io::Error> {
        let data = setup()?;
        let mut file = File::open(&data.tmp_file.path())?;
        let res = read_bytes(&mut file, 4, std::io::SeekFrom::Start(4))?;
        assert_eq!(res, (4u8..8).collect::<Vec<u8>>());
        Ok(())
    }

    #[test]
    fn test_read_all() -> Result<(), std::io::Error> {
        let data = setup()?;
        let result = read_all(&data.tmp_file.path(), std::io::SeekFrom::Start(17))?;
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
