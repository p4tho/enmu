use std::fs;
use std::path::{ PathBuf };

#[derive(thiserror::Error, Debug)]
pub enum EditorError {
    #[error("invalid file: {0}")]
    InvalidFile(String),

    #[error("I/O file system error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Editor {
    pub bytes: Vec<u8>,
}

impl Editor {
    pub fn new(path_buf: &PathBuf) -> Result<Self, EditorError> {
        if !path_buf.is_file() {
            return Err(EditorError::InvalidFile(
                "given path is not a file".into()
            ));
        }
        
        let bytes: Vec<u8> = fs::read(path_buf)?;

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
        
        Ok(Self {
            bytes
        })
    }
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
}