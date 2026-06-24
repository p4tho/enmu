use crate::types::{ Byte };

pub trait BytesConversion: Sized {
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

pub fn to_bytes<T: BytesConversion>(value: T) -> T::Bytes {
    value.to_bytes()
}

pub fn from_bytes<T: BytesConversion>(bytes: T::Bytes) -> T {
    T::from_bytes(bytes)
}

pub fn read_n_bytes_le<const N: usize>(buf: &[u8], pos: &mut usize) -> [Byte; N] {
    let bytes = &buf[*pos..*pos + N];
    let mut res = [0u8; N];
    
    res.copy_from_slice(bytes);
    res.reverse();
    
    *pos += N;
    
    res
}

#[cfg(test)]
mod test {
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
