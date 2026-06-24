// cargo build --release --target x86_64-pc-windows-msvc
// cargo build --release --target i686-pc-windows-msvc

use std::ffi::c_void;

// Official Windows entry point for DLLs
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _hmodule: *mut c_void,
    reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    
    if reason == DLL_PROCESS_ATTACH {
        // Initialization code runs immediately upon load
    }
    
    1 // Return success to host process
}

#[unsafe(no_mangle)]
pub extern "C" fn hello_world() {
    println!("Hello World!");
}
