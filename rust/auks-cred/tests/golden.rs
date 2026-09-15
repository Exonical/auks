//! Differential tests against the C-generated wire vectors.

use auks_cred::messages::{
    add_request, close, decode_dump_reply, decode_get_reply, dump, get_request, ping,
    remove_request,
};
use auks_cred::{Cred, CredError, CredInfo};
use auks_proto::{CRED_DATA_MAX_LENGTH, Message, MessageType, Reader, Writer};

fn blob() -> Vec<u8> {
    (0..1000).map(|value| (value & 0xff) as u8).collect()
}

fn vector(name: &str) -> &'static [u8] {
    match name {
        "ping_request" => include_bytes!("vectors/ping_request.bin"),
        "close_request" => include_bytes!("vectors/close_request.bin"),
        "dump_request" => include_bytes!("vectors/dump_request.bin"),
        "get_request_1234" => include_bytes!("vectors/get_request_1234.bin"),
        "remove_request_4321" => include_bytes!("vectors/remove_request_4321.bin"),
        "add_request" => include_bytes!("vectors/add_request.bin"),
        "get_reply" => include_bytes!("vectors/get_reply.bin"),
        "dump_reply" => include_bytes!("vectors/dump_reply.bin"),
        "error_reply" => include_bytes!("vectors/error_reply.bin"),
        _ => panic!("unknown vector"),
    }
}

#[test]
fn requests_match_c_vectors() {
    assert_eq!(ping().encode(), vector("ping_request"));
    assert_eq!(close().encode(), vector("close_request"));
    assert_eq!(dump().encode(), vector("dump_request"));
    assert_eq!(get_request(1234).encode(), vector("get_request_1234"));
    assert_eq!(remove_request(4321).encode(), vector("remove_request_4321"));
    assert_eq!(add_request(&blob()).encode(), vector("add_request"));
}

#[test]
fn all_vectors_decode_to_expected_types() {
    assert_eq!(
        Message::decode(vector("ping_request")).expect("ping").ty,
        MessageType::PingRequest
    );
    assert_eq!(
        Message::decode(vector("close_request")).expect("close").ty,
        MessageType::CloseRequest
    );
    assert_eq!(
        Message::decode(vector("dump_request")).expect("dump").ty,
        MessageType::DumpRequest
    );
    assert_eq!(
        Message::decode(vector("add_request")).expect("add").ty,
        MessageType::AddRequest
    );
    assert_eq!(
        Message::decode(vector("error_reply")).expect("error").ty,
        MessageType::ErrorReply
    );

    let get = Message::decode(vector("get_request_1234")).expect("get");
    assert_eq!(get.ty, MessageType::GetRequest);
    assert_eq!(get.reader().unpack_uid().expect("uid"), 1234);
    let remove = Message::decode(vector("remove_request_4321")).expect("remove");
    assert_eq!(remove.reader().unpack_uid().expect("uid"), 4321);
}

fn user_cred() -> Cred {
    Cred {
        info: CredInfo {
            principal: "user@EXAMPLE.COM".to_owned(),
            uid: 1234,
            starttime: 1_700_000_000,
            endtime: 1_700_036_000,
            renew_till: 1_700_604_800,
            addressless: true,
            crossrealm: false,
        },
        data: blob(),
        status: 0,
    }
}

#[test]
fn replies_decode_to_expected_credentials() {
    let get = Message::decode(vector("get_reply")).expect("get reply");
    assert_eq!(decode_get_reply(&get).expect("credential"), user_cred());

    let dump = Message::decode(vector("dump_reply")).expect("dump reply");
    let credentials = decode_dump_reply(&dump).expect("credentials");
    assert_eq!(credentials.len(), 2);
    assert_eq!(credentials[0], user_cred());
    assert_eq!(credentials[1].info.principal, "admin@EXAMPLE.COM");
    assert_eq!(credentials[1].info.uid, 4321);
    assert!(!credentials[1].info.addressless);
    assert!(credentials[1].info.crossrealm);
    assert_eq!(credentials[1].data, vec![0xaa; 17]);
}

#[test]
fn cred_pack_matches_c_cred_portion() {
    let message = Message::decode(vector("get_reply")).expect("get reply");
    let mut writer = Writer::new();
    user_cred().pack(&mut writer).expect("pack");
    assert_eq!(writer.into_inner(), message.body);
}

#[test]
fn malformed_and_boundary_credentials_are_rejected() {
    let mut writer = Writer::new();
    writer.pack_int(128 + 1);
    writer.pack_data(&[0; 129]);
    let bytes = writer.into_inner();
    let mut reader = Reader::new(&bytes);
    assert!(Cred::unpack(&mut reader).is_err());

    let mut writer = Writer::new();
    writer.pack_int(129);
    writer.pack_data(&[0; 129]);
    writer.pack_uid(1);
    writer.pack_int(0);
    writer.pack_int(0);
    writer.pack_int(0);
    writer.pack_int(1);
    writer.pack_int(0);
    writer.pack_int((CRED_DATA_MAX_LENGTH + 1) as i32);
    let bytes = writer.into_inner();
    let mut reader = Reader::new(&bytes);
    assert!(matches!(
        Cred::unpack(&mut reader),
        Err(CredError::InvalidMaxLength(_))
    ));
}

#[test]
fn principal_length_boundaries_are_enforced_on_pack() {
    let mut credential = user_cred();
    credential.info.principal = "x".repeat(128);
    credential
        .pack(&mut Writer::new())
        .expect("128-byte principal");
    credential.info.principal = "x".repeat(129);
    assert!(matches!(
        credential.pack(&mut Writer::new()),
        Err(CredError::InvalidPrincipal)
    ));
}
