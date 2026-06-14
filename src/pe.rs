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
    pub file_header: FileHeader,
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
        let e_lfanew: u32 = from_bytes(dos_header.e_lfanew);
        let file_header = Self::parse_file_header(&bytes, e_lfanew as usize);
        
        Ok(Self {
            bytes,
            dos_header,
            file_header,
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

    fn parse_file_header(buf: &[Byte], e_lfanew: usize) -> FileHeader {
        let nt_headers_buf = &buf[e_lfanew..];
        let mut pos: usize = 4; // 4 bytes reserved for signature (PE Magic Number)

        let machine = read_n_bytes_le::<2>(nt_headers_buf, &mut pos);
        let number_of_sections = read_n_bytes_le::<2>(nt_headers_buf, &mut pos);
        let time_date_stamp = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
        let pointer_to_symbol_table = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
        let number_of_symbols = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
        let size_of_optional_header = read_n_bytes_le::<2>(nt_headers_buf, &mut pos);
        let characteristics = read_n_bytes_le::<2>(nt_headers_buf, &mut pos);
        
        FileHeader {
            machine,
            number_of_sections,
            time_date_stamp,
            pointer_to_symbol_table,
            number_of_symbols,
            size_of_optional_header,
            characteristics,
        }
    }
}

/// 64-byte structure on all target architectures
/// Makes PE file an MS-DOS executable
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

/// 20-byte structure on all target architectures
/// Includes general info about the PE file
#[derive(Debug, PartialEq)]
pub struct FileHeader {
    machine: [Byte; 2],
    number_of_sections: [Byte; 2],
    time_date_stamp: [Byte; 4],
    pointer_to_symbol_table: [Byte; 4],
    number_of_symbols: [Byte; 4],
    size_of_optional_header: [Byte; 2],
    characteristics: [Byte; 2],
}

fn read_n_bytes_le<const N: usize>(buf: &[u8], pos: &mut usize) -> [Byte; N] {
    let bytes = &buf[*pos..*pos + N];
    let mut res = [0u8; N];
    
    res.copy_from_slice(bytes);
    res.reverse();
    
    *pos += N;
    
    res
}

trait BytesConversion: Sized {
    type Bytes;

    fn to_bytes(self) -> Self::Bytes;
    fn from_bytes(bytes: Self::Bytes) -> Self;
}

impl BytesConversion for u8 {
    type Bytes = [u8; 1];

    fn to_bytes(self) -> Self::Bytes {
        self.to_be_bytes()
    }

    fn from_bytes(bytes: Self::Bytes) -> Self {
        Self::from_be_bytes(bytes)
    }
}

impl BytesConversion for u16 {
    type Bytes = [u8; 2];

    fn to_bytes(self) -> Self::Bytes {
        self.to_be_bytes()
    }

    fn from_bytes(bytes: Self::Bytes) -> Self {
        Self::from_be_bytes(bytes)
    }
}

impl BytesConversion for u32 {
    type Bytes = [u8; 4];

    fn to_bytes(self) -> Self::Bytes {
        self.to_be_bytes()
    }

    fn from_bytes(bytes: Self::Bytes) -> Self {
        Self::from_be_bytes(bytes)
    }
}

impl BytesConversion for u64 {
    type Bytes = [u8; 8];

    fn to_bytes(self) -> Self::Bytes {
        self.to_be_bytes()
    }

    fn from_bytes(bytes: Self::Bytes) -> Self {
        Self::from_be_bytes(bytes)
    }
}

fn to_bytes<T: BytesConversion>(value: T) -> T::Bytes {
    value.to_bytes()
}

fn from_bytes<T: BytesConversion>(bytes: T::Bytes) -> T {
    T::from_bytes(bytes)
}

#[cfg(test)]
mod test {
    use super::*;

    mod bytes_conversion {
        use super::*;

        #[test]
        fn to_bytes_u8() {
            let x: u8 = 0x3a;
            let byte = to_bytes(x);
            let expected: [Byte; 1] = [0x3a];

            assert_eq!(byte, expected);
        }

        #[test]
        fn to_bytes_u16() {
            let x: u16 = 0x3ae2;
            let bytes = to_bytes(x);
            let expected: [Byte; 2] = [0x3a, 0xe2];

            assert_eq!(bytes, expected);
        }

        #[test]
        fn to_bytes_u32() {
            let x: u32 = 0x3ae200;
            let bytes = to_bytes(x);
            let expected: [Byte; 4] = [0x0, 0x3a, 0xe2, 0x0];

            assert_eq!(bytes, expected);
        }

        #[test]
        fn to_bytes_u64() {
            let x: u64 = 0x3ae200a1ff23b2;
            let bytes = to_bytes(x);
            let expected: [Byte; 8] = [0x0, 0x3a, 0xe2, 0x0, 0xa1, 0xff, 0x23, 0xb2];

            assert_eq!(bytes, expected);
        }

        #[test]
        fn from_bytes_u8() {
            let bytes: [Byte; 1] = [0x3a];
            let x: u8 = from_bytes(bytes);
            let expected: u8 = 0x3a;

            assert_eq!(x, expected);
        }
        
        #[test]
        fn from_bytes_u16() {
            let bytes: [Byte; 2] = [0x3a, 0xe2];
            let x: u16 = from_bytes(bytes);
            let expected: u16 = 0x3ae2;

            assert_eq!(x, expected);
        }

        #[test]
        fn from_bytes_u32() {
            let bytes: [Byte; 4] = [0x0, 0x3a, 0xe2, 0x0];
            let x: u32 = from_bytes(bytes);
            let expected: u32 = 0x3ae200;

            assert_eq!(x, expected);
        }

        #[test]
        fn from_bytes_u64() {
            let bytes: [Byte; 8] = [0x0, 0x3a, 0xe2, 0x0, 0xa1, 0xff, 0x23, 0xb2];
            let x: u64 = from_bytes(bytes);
            let expected: u64 = 0x3ae200a1ff23b2;

            assert_eq!(x, expected);
        }
    }

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
            e_magic: to_bytes(0x5a4d as u16),
            e_cblp: to_bytes(0x90 as u16),
            e_cp: to_bytes(0x3 as u16),
            e_crlc: to_bytes(0x0 as u16),
            e_cparhdr: to_bytes(0x4 as u16),
            e_minalloc: to_bytes(0x0 as u16),
            e_maxalloc: to_bytes(0xffff as u16),
            e_ss: to_bytes(0x0 as u16),
            e_sp: to_bytes(0xb8 as u16),
            e_csum: to_bytes(0x0 as u16),
            e_ip: to_bytes(0x0 as u16),
            e_cs: to_bytes(0x0 as u16),
            e_lfarlc: to_bytes(0x40 as u16),
            e_ovno: to_bytes(0x0 as u16),
            e_res: to_bytes(0x0 as u64),
            e_oemid: to_bytes(0x0 as u16),
            e_oeminfo: to_bytes(0x0 as u16),
            e_res2: [0u8; 20],
            e_lfanew: to_bytes(0xf8 as u32),
        };

        assert_eq!(dos_header, expected_dos_header);
    }

    #[test]
    fn correct_file_header_32() {
        let path_buf = PathBuf::from("tests/binaries/hello_gui_32.exe");
        let editor = Editor::new(&path_buf).unwrap();
        let dos_header = Editor::parse_dos_header(&editor.bytes);
        let e_lfanew: u32 = from_bytes(dos_header.e_lfanew);
        let file_header = Editor::parse_file_header(&editor.bytes, e_lfanew as usize);
        let expected_file_header = FileHeader {
            machine: to_bytes(0x14c as u16),
            number_of_sections: to_bytes(0x4 as u16),
            time_date_stamp: to_bytes(0x6a2a7552 as u32),
            pointer_to_symbol_table: to_bytes(0x0 as u32),
            number_of_symbols: to_bytes(0x0 as u32),
            size_of_optional_header: to_bytes(0xe0 as u16),
            characteristics: to_bytes(0x122 as u16),
        };

        assert_eq!(file_header, expected_file_header);
    }

    #[test]
    fn correct_file_header_64() {
        let path_buf = PathBuf::from("tests/binaries/hello_gui_64.exe");
        let editor = Editor::new(&path_buf).unwrap();
        let dos_header = Editor::parse_dos_header(&editor.bytes);
        let e_lfanew: u32 = from_bytes(dos_header.e_lfanew);
        let file_header = Editor::parse_file_header(&editor.bytes, e_lfanew as usize);
        let expected_file_header = FileHeader {
            machine: to_bytes(0x8664 as u16),
            number_of_sections: to_bytes(0x5 as u16),
            time_date_stamp: to_bytes(0x6a265bd1 as u32),
            pointer_to_symbol_table: to_bytes(0x0 as u32),
            number_of_symbols: to_bytes(0x0 as u32),
            size_of_optional_header: to_bytes(0xf0 as u16),
            characteristics: to_bytes(0x22 as u16),
        };

        assert_eq!(file_header, expected_file_header);
    }
}