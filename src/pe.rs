use std::fs;
use std::path::{ PathBuf };

const OPTIONAL_HDR32_MAGIC: [Byte; 2] = [0x01, 0x0b];

type Byte = u8;

#[derive(Debug, PartialEq)]
enum DifArch {
    B32([Byte; 4]),
    B64([Byte; 8]),
}

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
    pub optional_header: OptionalHeader,
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
        let optional_header = Self::parse_optional_header(&bytes, e_lfanew as usize);
        
        Ok(Self {
            bytes,
            dos_header,
            file_header,
            optional_header,
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

    fn parse_optional_header(buf: &[Byte], e_lfanew: usize) -> OptionalHeader {
        let nt_headers_buf = &buf[e_lfanew..];
        let mut pos: usize = 24; // 24 bytes reserved for signature and file header

        // Standard fields
        let magic = read_n_bytes_le::<2>(nt_headers_buf, &mut pos);
        let major_linker_ver = [nt_headers_buf[pos]]; pos += 1;
        let minor_linker_ver = [nt_headers_buf[pos]]; pos += 1;
        let size_of_code = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
        let size_of_init_data = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
        let size_of_uninit_data = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
        let addr_of_entry_point = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
        let base_of_code = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
        let base_of_data = if magic == OPTIONAL_HDR32_MAGIC {
            Some(read_n_bytes_le::<4>(nt_headers_buf, &mut pos))
        } else {
            None
        };
    
        // Windows-specific fields
        let image_base: DifArch;
        if magic == OPTIONAL_HDR32_MAGIC {
            image_base = DifArch::B32(read_n_bytes_le::<4>(nt_headers_buf, &mut pos));
        } else {
            image_base = DifArch::B64(read_n_bytes_le::<8>(nt_headers_buf, &mut pos));
        }
        
        let section_alignment = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
        let file_alignment = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
        let os_version_major = read_n_bytes_le::<2>(nt_headers_buf, &mut pos);
        let os_version_minor = read_n_bytes_le::<2>(nt_headers_buf, &mut pos);
        let image_version_major = read_n_bytes_le::<2>(nt_headers_buf, &mut pos);
        let image_version_minor = read_n_bytes_le::<2>(nt_headers_buf, &mut pos);
        let subsystem_version_major = read_n_bytes_le::<2>(nt_headers_buf, &mut pos);
        let subsystem_version_minor = read_n_bytes_le::<2>(nt_headers_buf, &mut pos);
        let win32_version_value = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
        let size_of_image = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
        let size_of_headers = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
        let checksum = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
        let subsystem = read_n_bytes_le::<2>(nt_headers_buf, &mut pos);
        let dll_characteristics = read_n_bytes_le::<2>(nt_headers_buf, &mut pos);
        let size_of_stack_reserve: DifArch;
        let size_of_stack_commit: DifArch;
        let size_of_heap_reserve: DifArch;
        let size_of_heap_commit: DifArch;
        if magic == OPTIONAL_HDR32_MAGIC {
            size_of_stack_reserve = DifArch::B32(read_n_bytes_le::<4>(nt_headers_buf, &mut pos));
            size_of_stack_commit = DifArch::B32(read_n_bytes_le::<4>(nt_headers_buf, &mut pos));
            size_of_heap_reserve = DifArch::B32(read_n_bytes_le::<4>(nt_headers_buf, &mut pos));
            size_of_heap_commit = DifArch::B32(read_n_bytes_le::<4>(nt_headers_buf, &mut pos));
        } else {
            size_of_stack_reserve = DifArch::B64(read_n_bytes_le::<8>(nt_headers_buf, &mut pos));
            size_of_stack_commit = DifArch::B64(read_n_bytes_le::<8>(nt_headers_buf, &mut pos));
            size_of_heap_reserve = DifArch::B64(read_n_bytes_le::<8>(nt_headers_buf, &mut pos));
            size_of_heap_commit = DifArch::B64(read_n_bytes_le::<8>(nt_headers_buf, &mut pos));
        }
        let loader_flags = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
        let number_of_rva_and_sizes = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
    
        let mut data_directories = [None; 16];
        let dir_count = std::cmp::min(from_bytes::<u32>(number_of_rva_and_sizes) as usize, 16);
        for i in 0..dir_count {
            let address = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
            let size = read_n_bytes_le::<4>(nt_headers_buf, &mut pos);
            
            data_directories[i] = Some(ImageDataDirectory {
                address,
                size,
            })
        }

        OptionalHeader {
            // Standard fields
            magic,
            major_linker_ver,
            minor_linker_ver,
            size_of_code,
            size_of_init_data,
            size_of_uninit_data,
            addr_of_entry_point,
            base_of_code,
            base_of_data,
        
            // Windows-specific fields
            image_base,
            section_alignment,
            file_alignment,
            os_version_major,
            os_version_minor,
            image_version_major,
            image_version_minor,
            subsystem_version_major,
            subsystem_version_minor,
            win32_version_value,
            size_of_image,
            size_of_headers,
            checksum,
            subsystem,
            dll_characteristics,
            size_of_stack_reserve,
            size_of_stack_commit,
            size_of_heap_reserve,
            size_of_heap_commit,
            loader_flags,
            number_of_rva_and_sizes,
            data_directories,
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

#[derive(Debug, PartialEq)]
pub struct OptionalHeader {
    // Standard fields
    magic: [Byte; 2],
    major_linker_ver: [Byte; 1],
    minor_linker_ver: [Byte; 1],
    size_of_code: [Byte; 4],
    size_of_init_data: [Byte; 4],
    size_of_uninit_data: [Byte; 4],
    addr_of_entry_point: [Byte; 4],
    base_of_code: [Byte; 4],
    base_of_data: Option<[Byte; 4]>,

    // Windows-specific fields
    image_base: DifArch,
    section_alignment: [Byte; 4],
    file_alignment: [Byte; 4],
    os_version_major: [Byte; 2],
    os_version_minor: [Byte; 2],
    image_version_major: [Byte; 2],
    image_version_minor: [Byte; 2],
    subsystem_version_major: [Byte; 2],
    subsystem_version_minor: [Byte; 2],
    win32_version_value: [Byte; 4],
    size_of_image: [Byte; 4],
    size_of_headers: [Byte; 4],
    checksum: [Byte; 4],
    subsystem: [Byte; 2],
    dll_characteristics: [Byte; 2],
    size_of_stack_reserve: DifArch,
    size_of_stack_commit: DifArch,
    size_of_heap_reserve: DifArch,
    size_of_heap_commit: DifArch,
    loader_flags: [Byte; 4],
    number_of_rva_and_sizes: [Byte; 4],
    data_directories: [Option<ImageDataDirectory>; 16],
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ImageDataDirectory {
    address: [Byte; 4],
    size: [Byte; 4],
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

    #[test]
    fn correct_optional_header_32() {
        let path_buf = PathBuf::from("tests/binaries/hello_gui_32.exe");
        let editor = Editor::new(&path_buf).unwrap();
        let dos_header = Editor::parse_dos_header(&editor.bytes);
        let e_lfanew: u32 = from_bytes(dos_header.e_lfanew);
        let optional_header = Editor::parse_optional_header(&editor.bytes, e_lfanew as usize);
        let expected_optional_header = OptionalHeader {
            magic: to_bytes(0x10b as u16),
            major_linker_ver: to_bytes(0xe as u8),
            minor_linker_ver: to_bytes(0x2c as u8),
            size_of_code: to_bytes(0x13600 as u32),
            size_of_init_data: to_bytes(0x6000 as u32),
            size_of_uninit_data: to_bytes(0x0 as u32),
            addr_of_entry_point: to_bytes(0x12aaa as u32),
            base_of_code: to_bytes(0x1000 as u32),
            base_of_data: Some(to_bytes(0x15000 as u32)),
        
            image_base: DifArch::B32(to_bytes(0x400000 as u32)),
            section_alignment: to_bytes(0x1000 as u32),
            file_alignment: to_bytes(0x200 as u32),
            os_version_major: to_bytes(0x6 as u16),
            os_version_minor: to_bytes(0x0 as u16),
            image_version_major: to_bytes(0x0 as u16),
            image_version_minor: to_bytes(0x0 as u16),
            subsystem_version_major: to_bytes(0x6 as u16),
            subsystem_version_minor: to_bytes(0x0 as u16),
            win32_version_value: to_bytes(0x0 as u32),
            size_of_image: to_bytes(0x1c000 as u32),
            size_of_headers: to_bytes(0x400 as u32),
            checksum: to_bytes(0x0 as u32),
            subsystem: to_bytes(0x2 as u16),
            dll_characteristics: to_bytes(0x8140 as u16),
            size_of_stack_reserve: DifArch::B32(to_bytes(0x100000 as u32)),
            size_of_stack_commit: DifArch::B32(to_bytes(0x1000 as u32)),
            size_of_heap_reserve: DifArch::B32(to_bytes(0x100000 as u32)),
            size_of_heap_commit: DifArch::B32(to_bytes(0x1000 as u32)),
            loader_flags: to_bytes(0x0 as u32),
            number_of_rva_and_sizes: to_bytes(0x10 as u32),
            data_directories: [
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x1924c as u32),
                    size: to_bytes(0xdc as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x1b000 as u32),
                    size: to_bytes(0xda0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x181c0 as u32),
                    size: to_bytes(0x54 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x18240 as u32),
                    size: to_bytes(0x18 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x18100 as u32),
                    size: to_bytes(0x40 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x15000 as u32),
                    size: to_bytes(0x164 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
            ],
        };


        assert_eq!(optional_header, expected_optional_header);
    }

    #[test]
    fn correct_optional_header_64() {
        let path_buf = PathBuf::from("tests/binaries/hello_gui_64.exe");
        let editor = Editor::new(&path_buf).unwrap();
        let dos_header = Editor::parse_dos_header(&editor.bytes);
        let e_lfanew: u32 = from_bytes(dos_header.e_lfanew);
        let optional_header = Editor::parse_optional_header(&editor.bytes, e_lfanew as usize);
        let expected_optional_header = OptionalHeader {
            magic: to_bytes(0x20b as u16),
            major_linker_ver: to_bytes(0xe as u8),
            minor_linker_ver: to_bytes(0x2c as u8),
            size_of_code: to_bytes(0x14400 as u32),
            size_of_init_data: to_bytes(0x8200 as u32),
            size_of_uninit_data: to_bytes(0x0 as u32),
            addr_of_entry_point: to_bytes(0x13620 as u32),
            base_of_code: to_bytes(0x1000 as u32),
            base_of_data: None,
        
            image_base: DifArch::B64(to_bytes(0x140000000 as u64)),
            section_alignment: to_bytes(0x1000 as u32),
            file_alignment: to_bytes(0x200 as u32),
            os_version_major: to_bytes(0x6 as u16),
            os_version_minor: to_bytes(0x0 as u16),
            image_version_major: to_bytes(0x0 as u16),
            image_version_minor: to_bytes(0x0 as u16),
            subsystem_version_major: to_bytes(0x6 as u16),
            subsystem_version_minor: to_bytes(0x0 as u16),
            win32_version_value: to_bytes(0x0 as u32),
            size_of_image: to_bytes(0x20000 as u32),
            size_of_headers: to_bytes(0x400 as u32),
            checksum: to_bytes(0x0 as u32),
            subsystem: to_bytes(0x2 as u16),
            dll_characteristics: to_bytes(0x8160 as u16),
            size_of_stack_reserve: DifArch::B64(to_bytes(0x100000 as u64)),
            size_of_stack_commit: DifArch::B64(to_bytes(0x1000 as u64)),
            size_of_heap_reserve: DifArch::B64(to_bytes(0x100000 as u64)),
            size_of_heap_commit: DifArch::B64(to_bytes(0x1000 as u64)),
            loader_flags: to_bytes(0x0 as u32),
            number_of_rva_and_sizes: to_bytes(0x10 as u32),
            data_directories: [
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x1c074 as u32),
                    size: to_bytes(0xdc as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x1e000 as u32),
                    size: to_bytes(0xdd4 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x1f000 as u32),
                    size: to_bytes(0x204 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x19ea0 as u32),
                    size: to_bytes(0x54 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x19f00 as u32),
                    size: to_bytes(0x28 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x19d60 as u32),
                    size: to_bytes(0x140 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x16000 as u32),
                    size: to_bytes(0x2c8 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
                Some(ImageDataDirectory {
                    address: to_bytes(0x0 as u32),
                    size: to_bytes(0x0 as u32),
                }),
            ],
        };


        assert_eq!(optional_header, expected_optional_header);
    }
}