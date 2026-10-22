use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Error(pub u32);

impl Error {
    pub const UNDEFINED: Self = Self(0);
    pub const ENCODE: Self = Self(1);
    pub const DECODE: Self = Self(2);
    pub const CLOSED: Self = Self(3);
    pub const TIMEOUT: Self = Self(4);
    pub const BAD_MESSAGE: Self = Self(5);
    pub const EMPTY_MESSAGE: Self = Self(6);
    pub const OVERSIZED_MESSAGE: Self = Self(7);
    pub const UNRECOGNIZED_MESSAGE: Self = Self(8);
    pub const PEER_NOT_FOUND: Self = Self(9);
    pub const BAD_ADDRESS: Self = Self(10);
    pub const BAD_KEY: Self = Self(11);
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => f.write_str("ErrUndefined"),
            1 => f.write_str("ErrEncode"),
            2 => f.write_str("ErrDecode"),
            3 => f.write_str("ErrClosed"),
            4 => f.write_str("ErrTimeout"),
            5 => f.write_str("ErrBadMessage"),
            6 => f.write_str("ErrEmptyMessage"),
            7 => f.write_str("ErrOversizedMessage"),
            8 => f.write_str("ErrUnrecognizedMessage"),
            9 => f.write_str("ErrPeerNotFound"),
            10 => f.write_str("ErrBadAddress"),
            11 => f.write_str("ErrBadKey"),
            n => write!(f, "Error({n})"),
        }
    }
}

impl std::error::Error for Error {}
