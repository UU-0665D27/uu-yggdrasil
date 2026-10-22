use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Error(pub u32);

impl Error {
    pub const UNDEFINED: Error = Error(0);
    pub const ENCODE: Error = Error(1);
    pub const DECODE: Error = Error(2);
    pub const Closed: Error = Error(3);
    pub const Timeout: Error = Error(4);
    pub const BadMessage: Error = Error(5);
    pub const EmptyMessage: Error = Error(6);
    pub const OversizedMessage: Error = Error(7);
    pub const UnrecognizedMessage: Error = Error(8);
    pub const PeerNotFound: Error = Error(9);
    pub const BadAddress: Error = Error(10);
    pub const BadKey: Error = Error(11);
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
            n => write!(f, "Error({})", n),
        }
    }
}

impl std::error::Error for Error {}
