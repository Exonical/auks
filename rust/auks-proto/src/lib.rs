//! Byte-compatible AUKS wire protocol primitives.

use std::convert::TryFrom;

use thiserror::Error;

/// Maximum input accepted by a reader in one data field.
pub const MAX_DATA_LENGTH: usize = 64 * 1024 * 1024;
/// Maximum principal length used by the credential wire format.
pub const PRINCIPAL_MAX_LENGTH: usize = 128;
/// Maximum serialized credential payload length.
pub const CRED_DATA_MAX_LENGTH: usize = 32768;

/// Errors returned while encoding or decoding protocol data.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtoError {
    /// The input ended before the requested number of bytes was available.
    #[error("truncated input: needed {needed} bytes, available {available}")]
    Truncated {
        /// Number of bytes requested.
        needed: usize,
        /// Number of bytes available.
        available: usize,
    },
    /// The message type number is not defined by the protocol.
    #[error("unknown message type {0}")]
    UnknownType(i32),
    /// A requested field exceeds the configured input limit.
    #[error("field is too large: requested {requested}, maximum {maximum}")]
    TooLarge {
        /// Number of bytes requested.
        requested: usize,
        /// Maximum permitted bytes.
        maximum: usize,
    },
}

/// AUKS request and reply type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum MessageType {
    /// Ping request.
    PingRequest = 0,
    /// List request.
    ListRequest = 1,
    /// Add request.
    AddRequest = 2,
    /// Get request.
    GetRequest = 3,
    /// Remove request.
    RemoveRequest = 4,
    /// Close request.
    CloseRequest = 5,
    /// Dump request.
    DumpRequest = 6,
    /// Credential dump request.
    CredDumpRequest = 7,
    /// Ping reply.
    PingReply = 20,
    /// Error reply.
    ErrorReply = 21,
    /// List reply.
    ListReply = 22,
    /// Add reply.
    AddReply = 23,
    /// Get reply.
    GetReply = 24,
    /// Remove reply.
    RemoveReply = 25,
    /// Dump reply.
    DumpReply = 26,
}

impl TryFrom<i32> for MessageType {
    type Error = ProtoError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        let ty = match value {
            0 => Self::PingRequest,
            1 => Self::ListRequest,
            2 => Self::AddRequest,
            3 => Self::GetRequest,
            4 => Self::RemoveRequest,
            5 => Self::CloseRequest,
            6 => Self::DumpRequest,
            7 => Self::CredDumpRequest,
            20 => Self::PingReply,
            21 => Self::ErrorReply,
            22 => Self::ListReply,
            23 => Self::AddReply,
            24 => Self::GetReply,
            25 => Self::RemoveReply,
            26 => Self::DumpReply,
            other => return Err(ProtoError::UnknownType(other)),
        };
        Ok(ty)
    }
}

impl From<MessageType> for i32 {
    fn from(value: MessageType) -> Self {
        value as i32
    }
}

/// A writer for the AUKS network byte order primitives.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Writer(Vec<u8>);

impl Writer {
    /// Creates an empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a signed 32-bit integer in big-endian order.
    pub fn pack_int(&mut self, value: i32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a UID using the C protocol's signed-int cast.
    pub fn pack_uid(&mut self, value: u32) {
        self.pack_int(value as i32);
    }

    /// Appends raw bytes without a length prefix.
    pub fn pack_data(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
    }

    /// Returns the encoded bytes.
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

/// A reader for AUKS network byte order primitives.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader over a byte slice.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Reads a signed 32-bit integer in big-endian order.
    pub fn unpack_int(&mut self) -> Result<i32, ProtoError> {
        let bytes = self.take(4)?;
        Ok(i32::from_be_bytes(bytes.try_into().expect("four bytes")))
    }

    /// Reads a UID using the C protocol's signed-int cast.
    pub fn unpack_uid(&mut self) -> Result<u32, ProtoError> {
        Ok(self.unpack_int()? as u32)
    }

    /// Reads a borrowed raw byte slice.
    pub fn unpack_data(&mut self, len: usize) -> Result<&'a [u8], ProtoError> {
        if len > MAX_DATA_LENGTH {
            return Err(ProtoError::TooLarge {
                requested: len,
                maximum: MAX_DATA_LENGTH,
            });
        }
        self.take(len)
    }

    /// Returns the unread portion of the input.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ProtoError> {
        let available = self.remaining();
        if len > available {
            return Err(ProtoError::Truncated {
                needed: len,
                available,
            });
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.buf[start..self.pos])
    }
}

/// A decoded AUKS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The message type.
    pub ty: MessageType,
    /// The encoded message body after the type integer.
    pub body: Vec<u8>,
}

impl Message {
    /// Creates a message with no body.
    pub fn new(ty: MessageType) -> Self {
        Self {
            ty,
            body: Vec::new(),
        }
    }

    /// Creates a message body containing a big-endian length and raw data.
    pub fn with_data(ty: MessageType, data: &[u8]) -> Self {
        let mut writer = Writer::new();
        writer.pack_int(data.len() as i32);
        writer.pack_data(data);
        Self {
            ty,
            body: writer.into_inner(),
        }
    }

    /// Encodes the type followed by the already encoded body.
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.pack_int(self.ty.into());
        writer.pack_data(&self.body);
        writer.into_inner()
    }

    /// Decodes a message from its wire representation.
    pub fn decode(data: &[u8]) -> Result<Self, ProtoError> {
        let mut reader = Reader::new(data);
        let ty = MessageType::try_from(reader.unpack_int()?)?;
        let body = reader.unpack_data(reader.remaining())?.to_vec();
        Ok(Self { ty, body })
    }

    /// Returns a mutable body writer.
    pub fn writer(&mut self) -> &mut Vec<u8> {
        &mut self.body
    }

    /// Returns a reader over the encoded body.
    pub fn reader(&self) -> Reader<'_> {
        Reader::new(&self.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_are_big_endian() {
        let mut writer = Writer::new();
        writer.pack_int(0x0102_0304);
        writer.pack_uid(u32::MAX);
        assert_eq!(writer.into_inner(), [1, 2, 3, 4, 255, 255, 255, 255]);
    }

    #[test]
    fn message_with_data_round_trips() {
        let message = Message::with_data(MessageType::AddRequest, &[1, 2, 3]);
        assert_eq!(Message::decode(&message.encode()).expect("decode"), message);
    }

    #[test]
    fn malformed_messages_are_rejected() {
        assert_eq!(
            Message::decode(&[0, 0, 0]).expect_err("truncated"),
            ProtoError::Truncated {
                needed: 4,
                available: 3
            }
        );
        assert_eq!(
            Message::decode(&[0, 0, 0, 99]).expect_err("unknown"),
            ProtoError::UnknownType(99)
        );
    }
}
