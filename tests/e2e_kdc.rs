//! End-to-end tests against a real KDC.
//!
//! Run with `scripts/e2e-kdc.sh`, which stands up a throwaway MIT KDC and a
//! `host/localhost` service keytab. The acceptor side is libgssapi's `ServerCtx`.

#![cfg(unix)]

use fabi_kerbsec::{AuthLevel, Context, Error, KerberosConfig};
use libgssapi::context::{CtxFlags, SecurityContext, ServerCtx};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::oid::{OidSet, GSS_MECH_KRB5};

fn config(auth: AuthLevel) -> KerberosConfig {
    KerberosConfig::builder()
        .realm("TEST.LOCAL")
        .target_host("localhost")
        // The test keytab holds `host/localhost` (MIT principals are case-sensitive)
        .spn_override(Some("host/localhost".to_owned()))
        .default_auth(auth)
        .build()
        .expect("config")
}

fn acceptor() -> ServerCtx {
    let mut mechs = OidSet::new().expect("oidset");
    mechs.add(&GSS_MECH_KRB5).expect("add mech");
    let cred = Cred::acquire(None, None, CredUsage::Accept, Some(&mechs)).expect("accept cred");
    ServerCtx::new(Some(cred))
}

/// Run the 3-leg handshake; returns the established (client, server) pair.
fn establish(auth: AuthLevel) -> (Context, ServerCtx) {
    let mut client = Context::new(config(auth)).expect("context");
    let mut server = acceptor();

    let ap_req = client.initial_token().expect("initial token");
    let ap_rep = server
        .step(&ap_req)
        .expect("server step 1")
        .expect("AP-REP");
    let third = client
        .accept_ap_rep(&ap_rep)
        .expect("accept_ap_rep")
        .expect("third leg");
    if !third.is_empty() && !server.is_complete() {
        server.step(&third).expect("server step 2");
    }
    assert!(client.established());
    (client, server)
}

fn concat(w: &fabi_kerbsec::IovWrap) -> Vec<u8> {
    [&w.header[..], &w.payload[..], &w.trailer[..]].concat()
}

#[test]
#[ignore = "requires a KDC; run scripts/e2e-kdc.sh"]
fn privacy_roundtrip_both_directions() {
    let (mut client, mut server) = establish(AuthLevel::Privacy);

    let wrapped = client.wrap_iov(b"hello server").expect("wrap");
    assert!(wrapped.conf, "Privacy wrap must report confidentiality");
    let plain = server.unwrap(&concat(&wrapped)).expect("server unwrap");
    assert_eq!(&plain[..], b"hello server");

    let reply = server.wrap(true, b"hello client").expect("server wrap");
    let plain = client.unwrap_iov(&reply).expect("client unwrap");
    assert_eq!(plain, b"hello client");
}

#[test]
#[ignore = "requires a KDC; run scripts/e2e-kdc.sh"]
fn privacy_context_rejects_integrity_only_token() {
    let (mut client, mut server) = establish(AuthLevel::Privacy);

    // A peer (or attacker) that signs but does not seal must not be accepted.
    let signed_only = server.wrap(false, b"not encrypted").expect("server wrap");
    let err = client.unwrap_iov(&signed_only).expect_err("must reject");
    assert!(
        matches!(err, Error::ConfidentialityNotProvided(_)),
        "unexpected error: {err:?}"
    );
}

#[test]
#[ignore = "requires a KDC; run scripts/e2e-kdc.sh"]
fn integrity_context_accepts_both_token_kinds() {
    let (mut client, mut server) = establish(AuthLevel::Integrity);

    let signed_only = server.wrap(false, b"plain").expect("wrap");
    assert_eq!(client.unwrap_iov(&signed_only).expect("unwrap"), b"plain");
    let sealed = server.wrap(true, b"sealed").expect("wrap");
    assert_eq!(client.unwrap_iov(&sealed).expect("unwrap"), b"sealed");
}

#[test]
#[ignore = "requires a KDC; run scripts/e2e-kdc.sh"]
fn per_call_privacy_works_on_integrity_context() {
    let (mut client, mut server) = establish(AuthLevel::Integrity);

    let sealed = client
        .wrap_iov_with(b"secret", AuthLevel::Privacy)
        .expect("per-call Privacy wrap");
    assert!(sealed.conf);
    assert_eq!(
        &server.unwrap(&concat(&sealed)).expect("unwrap")[..],
        b"secret"
    );

    let signed = client
        .wrap_iov_with(b"public", AuthLevel::Integrity)
        .expect("Integrity wrap");
    assert!(!signed.conf);
    assert_eq!(
        &server.unwrap(&concat(&signed)).expect("unwrap")[..],
        b"public"
    );
}

#[test]
#[ignore = "requires a KDC; run scripts/e2e-kdc.sh"]
fn negotiated_flags_include_integrity_conf_mutual() {
    let (_client, mut server) = establish(AuthLevel::Privacy);
    let flags = server.flags().expect("flags");
    assert!(flags.contains(CtxFlags::GSS_C_INTEG_FLAG));
    assert!(flags.contains(CtxFlags::GSS_C_CONF_FLAG));
    assert!(flags.contains(CtxFlags::GSS_C_MUTUAL_FLAG));
}

#[test]
#[ignore = "requires a KDC; run scripts/e2e-kdc.sh"]
fn wrap_size_limit_uses_the_mechanism() {
    let (client, _server) = establish(AuthLevel::Privacy);
    let limit = client.wrap_size_limit(1024, true);
    assert!(limit > 0 && limit < 1024, "limit = {limit}");
    // Integrity needs no more overhead than Privacy
    assert!(client.wrap_size_limit(1024, false) >= limit);
}

/// The DCE layout needs `gss_wrap_iov`, which is Linux-only here. This checks the
/// `auth_value` sizes; `dce_iov_roundtrip_both_directions` checks the peer accepts them.
#[cfg(all(target_os = "linux", feature = "iov"))]
#[test]
#[ignore = "requires a KDC; run scripts/e2e-kdc.sh"]
fn dce_iov_wrap_yields_ms_kile_auth_value_lengths() {
    use fabi_kerbsec::security::gss_iov::{
        DCE_INTEGRITY_AUTH_VALUE_LEN, DCE_PRIVACY_AUTH_VALUE_LEN,
    };

    let (mut client, _server) = establish(AuthLevel::Privacy);
    let header = [0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00].repeat(3);
    let sec_trailer = [0x10, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
    let plain = [0xAA_u8; 32];

    let mut stub = plain;
    let sealed = client
        .wrap_dce_iov(&header, &mut stub, &sec_trailer, true)
        .expect("sealed DCE wrap");
    assert_eq!(sealed.len(), DCE_PRIVACY_AUTH_VALUE_LEN);
    assert_eq!(
        client.dce_auth_value_len(true, 32).expect("len"),
        sealed.len()
    );
    assert_ne!(stub, plain, "the stub is encrypted in place");

    let mut stub = plain;
    let signed = client
        .wrap_dce_iov(&header, &mut stub, &sec_trailer, false)
        .expect("signed DCE wrap");
    assert_eq!(signed.len(), DCE_INTEGRITY_AUTH_VALUE_LEN);
    assert_eq!(
        client.dce_auth_value_len(false, 32).expect("len"),
        signed.len()
    );
    assert_eq!(stub, plain, "an integrity-only stub is left as is");

    let mut misaligned = [0u8; 12];
    assert!(matches!(
        client.wrap_dce_iov(&header, &mut misaligned, &sec_trailer, true),
        Err(Error::Iov(_))
    ));
}

/// Acceptor-side DCE wrap through the raw handle (libgssapi wraps no IOV calls).
#[cfg(all(target_os = "linux", feature = "iov"))]
#[allow(clippy::needless_pass_by_ref_mut)] // the call advances `server`'s sequence state
fn server_wrap_dce(
    server: &mut ServerCtx,
    header: &[u8],
    stub: &mut [u8],
    sec_trailer: &[u8],
    conf_req: bool,
) -> Vec<u8> {
    use fabi_kerbsec::ffi;
    use fabi_kerbsec::security::gss_iov::build_dce_iov_descriptors;

    let mut auth_value = vec![0u8; 256];
    let mut iov = build_dce_iov_descriptors(header, stub, sec_trailer, &mut auth_value);
    let (mut minor, mut conf_state) = (0, 0);
    // SAFETY: every buffer outlives the call; the handle is owned by `server`,
    // which is mutably borrowed for it.
    let major = unsafe {
        ffi::gss_wrap_iov(
            &mut minor,
            server.raw_ctx().cast(),
            i32::from(conf_req),
            ffi::GSS_C_QOP_DEFAULT,
            &mut conf_state,
            iov.as_mut_ptr(),
            iov.len() as i32,
        )
    };
    assert_eq!(major, ffi::GSS_S_COMPLETE, "server wrap, minor {minor:#x}");
    assert_eq!(conf_state != 0, conf_req);
    let len = iov[3].buffer.length;
    auth_value.truncate(len);
    auth_value
}

/// Acceptor-side DCE unwrap; returns whether the PDU was encrypted, or the
/// GSS major status on failure.
#[cfg(all(target_os = "linux", feature = "iov"))]
#[allow(clippy::needless_pass_by_ref_mut)] // as in `server_wrap_dce`
fn server_unwrap_dce(
    server: &mut ServerCtx,
    header: &[u8],
    stub: &mut [u8],
    sec_trailer: &[u8],
    auth_value: &[u8],
) -> Result<bool, u32> {
    use fabi_kerbsec::ffi;
    use fabi_kerbsec::security::gss_iov::build_dce_iov_descriptors;

    let mut auth_value = auth_value.to_vec();
    let mut iov = build_dce_iov_descriptors(header, stub, sec_trailer, &mut auth_value);
    let (mut minor, mut conf_state, mut qop_state) = (0, 0, 0);
    // SAFETY: as in `server_wrap_dce`.
    let major = unsafe {
        ffi::gss_unwrap_iov(
            &mut minor,
            server.raw_ctx().cast(),
            &mut conf_state,
            &mut qop_state,
            iov.as_mut_ptr(),
            iov.len() as i32,
        )
    };
    if major == ffi::GSS_S_COMPLETE {
        Ok(conf_state != 0)
    } else {
        Err(major)
    }
}

#[cfg(all(target_os = "linux", feature = "iov"))]
#[test]
#[ignore = "requires a KDC; run scripts/e2e-kdc.sh"]
fn dce_iov_roundtrip_both_directions() {
    let (mut client, mut server) = establish(AuthLevel::Privacy);
    let header = [0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00].repeat(3);
    let sec_trailer = [0x10, 0x06, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00];
    let plain = *b"a 32-byte DCE/RPC request stub!!";

    // Client to server, sealed. A tampered header is tried first: the signature
    // covers the SIGN_ONLY buffers, and a rejected token does not consume its
    // sequence number.
    let mut stub = plain;
    let auth_value = client
        .wrap_dce_iov(&header, &mut stub, &sec_trailer, true)
        .expect("client wrap");
    let mut tampered = header.clone();
    tampered[2] ^= 0x01;
    let mut stub_copy = stub;
    assert!(
        server_unwrap_dce(
            &mut server,
            &tampered,
            &mut stub_copy,
            &sec_trailer,
            &auth_value
        )
        .is_err(),
        "a modified header must fail verification"
    );
    let encrypted = server_unwrap_dce(&mut server, &header, &mut stub, &sec_trailer, &auth_value)
        .expect("server unwrap");
    assert!(encrypted);
    assert_eq!(stub, plain);

    // Server to client, sealed
    let mut stub = plain;
    let auth_value = server_wrap_dce(&mut server, &header, &mut stub, &sec_trailer, true);
    assert_ne!(stub, plain);
    client
        .unwrap_dce_iov(&header, &mut stub, &sec_trailer, &auth_value, true)
        .expect("client unwrap");
    assert_eq!(stub, plain);

    // Server to client, signed only, while the client expects encryption
    let mut stub = plain;
    let auth_value = server_wrap_dce(&mut server, &header, &mut stub, &sec_trailer, false);
    let err = client
        .unwrap_dce_iov(&header, &mut stub, &sec_trailer, &auth_value, true)
        .expect_err("must reject an unencrypted PDU");
    assert!(
        matches!(err, Error::ConfidentialityNotProvided(_)),
        "unexpected error: {err:?}"
    );
    assert_eq!(stub, [0u8; 32], "the rejected stub is zeroized");
}

/// Acceptor-side `gss_get_mic` through the raw handle.
#[allow(clippy::needless_pass_by_ref_mut)] // the call advances `server`'s sequence state
fn server_get_mic(server: &mut ServerCtx, message: &[u8]) -> Vec<u8> {
    use fabi_kerbsec::ffi;

    let mut input = ffi::gss_buffer_desc {
        length: message.len(),
        value: message.as_ptr().cast_mut().cast(),
    };
    let mut output = ffi::gss_buffer_desc {
        length: 0,
        value: std::ptr::null_mut(),
    };
    let mut minor = 0;
    // SAFETY: `input` outlives the call and is only read; GSS allocates
    // `output`, which is released below.
    let major = unsafe {
        ffi::gss_get_mic(
            &mut minor,
            server.raw_ctx().cast(),
            ffi::GSS_C_QOP_DEFAULT,
            &mut input,
            &mut output,
        )
    };
    assert_eq!(
        major,
        ffi::GSS_S_COMPLETE,
        "server get_mic, minor {minor:#x}"
    );
    // SAFETY: GSS reports `length` valid bytes at `value`, and allocated them.
    unsafe {
        let mic = std::slice::from_raw_parts(output.value.cast::<u8>(), output.length).to_vec();
        ffi::gss_release_buffer(&mut minor, &mut output);
        mic
    }
}

/// Acceptor-side `gss_verify_mic`; whether the MIC matched.
#[allow(clippy::needless_pass_by_ref_mut)] // as in `server_get_mic`
fn server_verify_mic(server: &mut ServerCtx, message: &[u8], mic: &[u8]) -> bool {
    use fabi_kerbsec::ffi;

    let mut message_buf = ffi::gss_buffer_desc {
        length: message.len(),
        value: message.as_ptr().cast_mut().cast(),
    };
    let mut token_buf = ffi::gss_buffer_desc {
        length: mic.len(),
        value: mic.as_ptr().cast_mut().cast(),
    };
    let (mut minor, mut qop_state) = (0, 0);
    // SAFETY: both buffers outlive the call and are only read.
    let major = unsafe {
        ffi::gss_verify_mic(
            &mut minor,
            server.raw_ctx().cast(),
            &mut message_buf,
            &mut token_buf,
            &mut qop_state,
        )
    };
    major == ffi::GSS_S_COMPLETE
}

/// DCE/RPC packet integrity signs with MIC tokens. Tampered messages are tried
/// before the genuine ones so a rejection never consumes a sequence number.
#[test]
#[ignore = "requires a KDC; run scripts/e2e-kdc.sh"]
fn mic_roundtrip_both_directions() {
    use fabi_kerbsec::security::gss_iov::DCE_INTEGRITY_AUTH_VALUE_LEN;

    let (mut client, mut server) = establish(AuthLevel::Integrity);

    let request = b"PDU header, stub and sec_trailer";
    let mic = client.get_mic(request).expect("client MIC");
    assert_eq!(
        mic.len(),
        DCE_INTEGRITY_AUTH_VALUE_LEN,
        "MIC = integrity auth_value"
    );
    let mut tampered = request.to_vec();
    tampered[0] ^= 0x01;
    assert!(!server_verify_mic(&mut server, &tampered, &mic));
    assert!(server_verify_mic(&mut server, request, &mic));

    let response = b"a response the server signed";
    let mic = server_get_mic(&mut server, response);
    let mut tampered = response.to_vec();
    tampered[0] ^= 0x01;
    assert!(client.verify_mic(&tampered, &mic).is_err());
    client.verify_mic(response, &mic).expect("client verify");
}

#[test]
#[ignore = "requires a KDC; run scripts/e2e-kdc.sh"]
fn handshake_state_is_enforced() {
    let mut client = Context::new(config(AuthLevel::Privacy)).expect("context");

    // AP-REP before AP-REQ
    assert!(matches!(
        client.accept_ap_rep(b"x"),
        Err(Error::HandshakeState(_))
    ));

    let mut server = acceptor();
    let ap_req = client.initial_token().expect("initial token");

    // initial_token twice; bindings after the first leg
    assert!(matches!(
        client.initial_token(),
        Err(Error::HandshakeState(_))
    ));
    assert!(matches!(
        client.set_channel_bindings(None),
        Err(Error::HandshakeState(_))
    ));

    let ap_rep = server.step(&ap_req).expect("step").expect("AP-REP");
    client.accept_ap_rep(&ap_rep).expect("accept");
    assert!(matches!(
        client.accept_ap_rep(&ap_rep),
        Err(Error::HandshakeState(_))
    ));
}
