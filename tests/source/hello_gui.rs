// cargo build --release --target x86_64-pc-windows-msvc
// cargo build --release --target i686-pc-windows-msvc

#![windows_subsystem = "windows"]

use std::ptr::null_mut;

// Link to the Windows User32 library for a GUI popup
#[link(name = "user32")]
unsafe extern "system" {
    fn MessageBoxW(
        hwnd: *mut std::ffi::c_void,
        lpText: *const u16,
        lpCaption: *const u16,
        uType: u32,
    ) -> i32;
}

fn main() {
    let text: Vec<u16> = "Hello World!".encode_utf16().chain(Some(0)).collect();
    let caption: Vec<u16> = "PE Test Target".encode_utf16().chain(Some(0)).collect();

    unsafe {
        MessageBoxW(null_mut(), text.as_ptr(), caption.as_ptr(), 0x00000000);
    }
}
