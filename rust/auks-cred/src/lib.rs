//! Rust representation of the serialized AUKS credential.

use std::str::Utf8Error;

use auks_proto::{CRED_DATA_MAX_LENGTH, PRINCIPAL_MAX_LENGTH, ProtoError, Reader, Writer};
use thiserror::Error;

/// Errors returned while encoding or decoding credentials.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CredError {
    /// The principal contains a NUL byte or exceeds the wire limit.
    #[error("invalid principal")]
    InvalidPrincipal,
    /// The principal bytes are not valid UTF-8.
    #[error("principal is not UTF-8: {0}")]
    InvalidPrincipalUtf8(#[from] Utf8Error),
    /// The credential blob exceeds the wire limit.
    #[error("credential data is too large: {0}")]
    DataTooLarge(usize),
    /// The wire data is malformed.
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtoError),
    /// The credential max length is invalid.
    #[error("invalid credential max length {0}")]
    InvalidMaxLength(i32),
    /// The credential length exceeds its max length.
    #[error("credential length {length} exceeds max length {max_length}")]
    InvalidLength {
        /// Decoded credential length.
        length: usize,
        /// Decoded maximum length.
        max_length: usize,
    },
    /// A boolean field has an invalid encoded value.
    #[error("invalid boolean value {0}")]
    InvalidBoolean(i32),
    /// The message has an unexpected type.
    #[error("unexpected message type")]
    UnexpectedMessageType,
}

/// Credential metadata serialized by AUKS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredInfo {
    /// Kerberos principal name.
    pub principal: String,
    /// Unix user ID.
    pub uid: u32,
    /// Credential start time.
    pub starttime: i32,
    /// Credential end time.
    pub endtime: i32,
    /// Credential renewal deadline.
    pub renew_till: i32,
    /// Whether the credential is addressless.
    pub addressless: bool,
    /// Whether the credential crossed a realm boundary.
    pub crossrealm: bool,
}

/// A serialized Kerberos credential and its metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cred {
    /// Credential metadata.
    pub info: CredInfo,
    /// Serialized credential bytes.
    pub data: Vec<u8>,
    /// AUKS status code.
    pub status: i32,
}

impl Cred {
    /// Packs a credential using the C wire layout.
    pub fn pack(&self, writer: &mut Writer) -> Result<(), CredError> {
        let principal = self.info.principal.as_bytes();
        if principal.len() > PRINCIPAL_MAX_LENGTH || principal.contains(&0) {
            return Err(CredError::InvalidPrincipal);
        }
        if self.data.len() > CRED_DATA_MAX_LENGTH {
            return Err(CredError::DataTooLarge(self.data.len()));
        }

        writer.pack_int((PRINCIPAL_MAX_LENGTH + 1) as i32);
        let mut principal_buf = [0_u8; PRINCIPAL_MAX_LENGTH + 1];
        principal_buf[..principal.len()].copy_from_slice(principal);
        writer.pack_data(&principal_buf);
        writer.pack_uid(self.info.uid);
        writer.pack_int(self.info.starttime);
        writer.pack_int(self.info.endtime);
        writer.pack_int(self.info.renew_till);
        writer.pack_int(self.info.addressless as i32);
        writer.pack_int(self.info.crossrealm as i32);
        writer.pack_int(CRED_DATA_MAX_LENGTH as i32);
        writer.pack_int(self.data.len() as i32);
        let mut data = vec![0_u8; CRED_DATA_MAX_LENGTH];
        data[..self.data.len()].copy_from_slice(&self.data);
        writer.pack_data(&data);
        writer.pack_int(self.status);
        Ok(())
    }

    /// Unpacks a credential using the C wire layout.
    pub fn unpack(reader: &mut Reader<'_>) -> Result<Self, CredError> {
        let principal_length = reader.unpack_int()?;
        if principal_length != (PRINCIPAL_MAX_LENGTH + 1) as i32 {
            return Err(CredError::InvalidLength {
                length: principal_length.max(0) as usize,
                max_length: PRINCIPAL_MAX_LENGTH + 1,
            });
        }
        let principal_bytes = reader.unpack_data(PRINCIPAL_MAX_LENGTH + 1)?;
        let principal_end = principal_bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(principal_bytes.len());
        let principal = std::str::from_utf8(&principal_bytes[..principal_end])?.to_owned();
        let uid = reader.unpack_uid()?;
        let starttime = reader.unpack_int()?;
        let endtime = reader.unpack_int()?;
        let renew_till = reader.unpack_int()?;
        let addressless = reader.unpack_int()? != 0;
        let crossrealm = reader.unpack_int()? != 0;
        let max_length = reader.unpack_int()?;
        if !(0..=(CRED_DATA_MAX_LENGTH as i32)).contains(&max_length) {
            return Err(CredError::InvalidMaxLength(max_length));
        }
        let length = reader.unpack_int()?;
        if length < 0 {
            return Err(CredError::InvalidLength {
                length: usize::MAX,
                max_length: max_length as usize,
            });
        }
        let length = length as usize;
        let max_length = max_length as usize;
        if length > CRED_DATA_MAX_LENGTH {
            return Err(CredError::DataTooLarge(length));
        }
        if length > max_length {
            return Err(CredError::InvalidLength { length, max_length });
        }
        let data = reader
            .unpack_data(max_length)?
            .get(..length)
            .unwrap_or(&[])
            .to_vec();
        let status = reader.unpack_int()?;
        Ok(Self {
            info: CredInfo {
                principal,
                uid,
                starttime,
                endtime,
                renew_till,
                addressless,
                crossrealm,
            },
            data,
            status,
        })
    }
}

pub mod messages {
    //! Helpers for constructing and decoding credential messages.

    use super::{Cred, CredError};
    use auks_proto::{Message, MessageType, ProtoError, Writer};

    /// Creates a GET request.
    pub fn get_request(uid: u32) -> Message {
        let mut message = Message::new(MessageType::GetRequest);
        let mut writer = Writer::new();
        writer.pack_uid(uid);
        message.body = writer.into_inner();
        message
    }

    /// Creates a REMOVE request.
    pub fn remove_request(uid: u32) -> Message {
        let mut message = Message::new(MessageType::RemoveRequest);
        let mut writer = Writer::new();
        writer.pack_uid(uid);
        message.body = writer.into_inner();
        message
    }

    /// Creates an ADD request containing an unparsed credential blob.
    pub fn add_request(blob: &[u8]) -> Message {
        Message::with_data(MessageType::AddRequest, blob)
    }

    /// Creates a PING request.
    pub fn ping() -> Message {
        Message::new(MessageType::PingRequest)
    }

    /// Creates a CLOSE request.
    pub fn close() -> Message {
        Message::new(MessageType::CloseRequest)
    }

    /// Creates a DUMP request.
    pub fn dump() -> Message {
        Message::new(MessageType::DumpRequest)
    }

    /// Decodes a GET reply.
    pub fn decode_get_reply(message: &Message) -> Result<Cred, CredError> {
        if message.ty != MessageType::GetReply {
            return Err(CredError::UnexpectedMessageType);
        }
        Cred::unpack(&mut message.reader())
    }

    /// Decodes a DUMP reply.
    pub fn decode_dump_reply(message: &Message) -> Result<Vec<Cred>, CredError> {
        if message.ty != MessageType::DumpReply {
            return Err(CredError::UnexpectedMessageType);
        }
        let mut reader = message.reader();
        let count = reader.unpack_int()?;
        if count < 0 {
            return Err(CredError::Protocol(ProtoError::TooLarge {
                requested: usize::MAX,
                maximum: i32::MAX as usize,
            }));
        }
        let mut creds = Vec::with_capacity(count as usize);
        for _ in 0..count {
            creds.push(Cred::unpack(&mut reader)?);
        }
        Ok(creds)
    }
}
