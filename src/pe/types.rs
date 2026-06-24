pub type Byte = u8;

#[derive(Debug, PartialEq)]
pub enum DifArch {
    B32([Byte; 4]),
    B64([Byte; 8]),
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
    pub machine: [Byte; 2],
    pub number_of_sections: [Byte; 2],
    pub time_date_stamp: [Byte; 4],
    pub pointer_to_symbol_table: [Byte; 4],
    pub number_of_symbols: [Byte; 4],
    pub size_of_optional_header: [Byte; 2],
    pub characteristics: [Byte; 2],
}

#[derive(Debug, PartialEq)]
pub struct OptionalHeader {
    // Standard fields
    pub magic: [Byte; 2],
    pub major_linker_ver: [Byte; 1],
    pub minor_linker_ver: [Byte; 1],
    pub size_of_code: [Byte; 4],
    pub size_of_init_data: [Byte; 4],
    pub size_of_uninit_data: [Byte; 4],
    pub addr_of_entry_point: [Byte; 4],
    pub base_of_code: [Byte; 4],
    pub base_of_data: Option<[Byte; 4]>,

    // Windows-specific fields
    pub image_base: DifArch,
    pub section_alignment: [Byte; 4],
    pub file_alignment: [Byte; 4],
    pub os_version_major: [Byte; 2],
    pub os_version_minor: [Byte; 2],
    pub image_version_major: [Byte; 2],
    pub image_version_minor: [Byte; 2],
    pub subsystem_version_major: [Byte; 2],
    pub subsystem_version_minor: [Byte; 2],
    pub win32_version_value: [Byte; 4],
    pub size_of_image: [Byte; 4],
    pub size_of_headers: [Byte; 4],
    pub checksum: [Byte; 4],
    pub subsystem: [Byte; 2],
    pub dll_characteristics: [Byte; 2],
    pub size_of_stack_reserve: DifArch,
    pub size_of_stack_commit: DifArch,
    pub size_of_heap_reserve: DifArch,
    pub size_of_heap_commit: DifArch,
    pub loader_flags: [Byte; 4],
    pub number_of_rva_and_sizes: [Byte; 4],
    pub data_directories: [Option<ImageDataDirectory>; 16],
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ImageDataDirectory {
    pub address: [Byte; 4],
    pub size: [Byte; 4],
}

pub type SectionTable = Vec<SectionTableEntry>;

#[derive(Debug, PartialEq)]
pub struct SectionTableEntry {
    pub name: [Byte; 8],
    pub virtual_size: [Byte; 4],
    pub virtual_addr: [Byte; 4],
    pub size_of_raw_data: [Byte; 4],
    pub pointer_to_raw_data: [Byte; 4],
    pub pointer_to_relocations: [Byte; 4],
    pub pointer_to_line_nums: [Byte; 4],
    pub number_of_relocations: [Byte; 2],
    pub number_of_line_nums: [Byte; 2],
    pub characteristics: [Byte; 4],
}
