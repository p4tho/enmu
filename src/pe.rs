use std::fs;
use std::path::{ PathBuf };

type Byte = u8;

#[derive(thiserror::Error, Debug)]
pub enum EditorError {
    #[error("invalid file: {0}")]
    InvalidFile(String),

    #[error("I/O file system error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Editor {
    pub bytes: Vec<u8>,
    pub dos_header: DosHeader,
}

impl Editor {
    pub fn new(path_buf: &PathBuf) -> Result<Self, EditorError> {
        if !path_buf.is_file() {
            return Err(EditorError::InvalidFile(
                "given path is not a file".into()
            ));
        }
        
        let bytes: Vec<Byte> = fs::read(path_buf)?;

        if bytes.len() < 2 {
            return Err(EditorError::InvalidFile(
                "file is not long enough".into()
            ));
        }

        if &bytes[0..2] != b"MZ" {
            return Err(EditorError::InvalidFile(
                "file is not a windows executable".into()
            ));
        }

        let dos_header = Self::parse_dos_header(&bytes);
        
        Ok(Self {
            bytes,
            dos_header,
        })
    }

    fn parse_dos_header(buf: &[Byte]) -> DosHeader {
        let mut pos: usize = 0;

        let e_magic = read_n_bytes_le::<2>(buf, &mut pos);
        let e_cblp = read_n_bytes_le::<2>(buf, &mut pos);
        let e_cp = read_n_bytes_le::<2>(buf, &mut pos);
        let e_crlc = read_n_bytes_le::<2>(buf, &mut pos);
        let e_cparhdr = read_n_bytes_le::<2>(buf, &mut pos);
        let e_minalloc = read_n_bytes_le::<2>(buf, &mut pos);
        let e_maxalloc = read_n_bytes_le::<2>(buf, &mut pos);
        let e_ss = read_n_bytes_le::<2>(buf, &mut pos);
        let e_sp = read_n_bytes_le::<2>(buf, &mut pos);
        let e_csum = read_n_bytes_le::<2>(buf, &mut pos);
        let e_ip = read_n_bytes_le::<2>(buf, &mut pos);
        let e_cs = read_n_bytes_le::<2>(buf, &mut pos);
        let e_lfarlc = read_n_bytes_le::<2>(buf, &mut pos);
        let e_ovno = read_n_bytes_le::<2>(buf, &mut pos);
        let e_res = read_n_bytes_le::<8>(buf, &mut pos);
        let e_oemid = read_n_bytes_le::<2>(buf, &mut pos);
        let e_oeminfo = read_n_bytes_le::<2>(buf, &mut pos);
        let e_res2 = read_n_bytes_le::<20>(buf, &mut pos);
        let e_lfanew = read_n_bytes_le::<4>(buf, &mut pos);

        DosHeader {
            e_magic,
            e_cblp,
            e_cp,
            e_crlc,
            e_cparhdr,
            e_minalloc,
            e_maxalloc,
            e_ss,
            e_sp,
            e_csum,
            e_ip,
            e_cs,
            e_lfarlc,
            e_ovno,
            e_res,
            e_oemid,
            e_oeminfo,
            e_res2,
            e_lfanew,
        }
    }
}

/// 64-byte structure on all target architectures and makes PE an MS-DOS executable
#[derive(Debug, PartialEq)]
pub struct DosHeader {
    pub e_magic: [Byte; 2],
    pub e_cblp: [Byte; 2],
    pub e_cp: [Byte; 2],
    pub e_crlc: [Byte; 2],
    pub e_cparhdr: [Byte; 2],
    pub e_minalloc: [Byte; 2],
    pub e_maxalloc: [Byte; 2],
    pub e_ss: [Byte; 2],
    pub e_sp: [Byte; 2],
    pub e_csum: [Byte; 2],
    pub e_ip: [Byte; 2],
    pub e_cs: [Byte; 2],
    pub e_lfarlc: [Byte; 2],
    pub e_ovno: [Byte; 2],
    pub e_res: [Byte; 8],
    pub e_oemid: [Byte; 2],
    pub e_oeminfo: [Byte; 2],
    pub e_res2: [Byte; 20],
    pub e_lfanew: [Byte; 4]
}

fn read_n_bytes_le<const N: usize>(buf: &[u8], pos: &mut usize) -> [Byte; N] {
    let bytes = &buf[*pos..*pos + N];
    let mut res = [0u8; N];
    
    res.copy_from_slice(bytes);
    res.reverse();
    
    *pos += N;
    
    res
}

trait ToBytes {
    type Output;

    fn to_bytes(self) -> Self::Output;
}

impl ToBytes for u8 {
    type Output = [u8; 1];

    fn to_bytes(self) -> Self::Output {
        self.to_be_bytes()
    }
}

impl ToBytes for u16 {
    type Output = [u8; 2];

    fn to_bytes(self) -> Self::Output {
        self.to_be_bytes()
    }
}

impl ToBytes for u32 {
    type Output = [u8; 4];

    fn to_bytes(self) -> Self::Output {
        self.to_be_bytes()
    }
}

impl ToBytes for u64 {
    type Output = [u8; 8];

    fn to_bytes(self) -> Self::Output {
        self.to_be_bytes()
    }
}

fn into_bytes<T: ToBytes>(value: T) -> T::Output {
    value.to_bytes()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn valid_new_editor() {
        let path_buf = PathBuf::from("tests/binaries/hello_32.dll");
        let editor = Editor::new(&path_buf);

        assert!(editor.is_ok());
    }

    #[test]
    fn invalid_new_editor() {
        let path_buf = PathBuf::from("tests/binaries/empty.dll");
        let editor = Editor::new(&path_buf);

        assert!(editor.is_err());
    }

    #[test]
    fn correct_dos_header() {
        let path_buf = PathBuf::from("tests/binaries/hello_32.dll");
        let editor = Editor::new(&path_buf).unwrap();
        let dos_header = Editor::parse_dos_header(&editor.bytes);
        let expected_dos_header = DosHeader {
            e_magic: into_bytes(0x5a4d as u16),
            e_cblp: into_bytes(0x90 as u16),
            e_cp: into_bytes(0x3 as u16),
            e_crlc: into_bytes(0x0 as u16),
            e_cparhdr: into_bytes(0x4 as u16),
            e_minalloc: into_bytes(0x0 as u16),
            e_maxalloc: into_bytes(0xffff as u16),
            e_ss: into_bytes(0x0 as u16),
            e_sp: into_bytes(0xb8 as u16),
            e_csum: into_bytes(0x0 as u16),
            e_ip: into_bytes(0x0 as u16),
            e_cs: into_bytes(0x0 as u16),
            e_lfarlc: into_bytes(0x40 as u16),
            e_ovno: into_bytes(0x0 as u16),
            e_res: into_bytes(0x0 as u64),
            e_oemid: into_bytes(0x0 as u16),
            e_oeminfo: into_bytes(0x0 as u16),
            e_res2: [0u8; 20],
            e_lfanew: into_bytes(0xf8 as u32),
        };

        assert_eq!(dos_header, expected_dos_header);
    }
}