//! CTAP2 CBOR for the Windows plugin authenticator: decoding `authenticatorMakeCredential` /
//! `authenticatorGetAssertion` requests and encoding their responses, plus the
//! `authenticatorGetInfo` blob given to Windows at registration.
//!
//! Wire format, checked against `webauthn.dll` on Windows 11 build 26300
//! (`WebAuthNDecode*Request` / `WebAuthNEncode*Response`): requests are the bare CBOR map
//! (no CTAP command byte), responses are the bare CBOR map (no CTAP status byte), with keys in
//! CTAP2 canonical order. The response test vectors below are byte-for-byte what
//! `WebAuthNEncodeMakeCredentialResponse` / `WebAuthNEncodeGetAssertionResponse` produce.

use ciborium::Value;
use pass_agent::{PlatformAssertion, PlatformCreateRequest, PlatformGetRequest};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtapError(pub String);

impl std::fmt::Display for CtapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid CTAP2 request: {}", self.0)
    }
}

type Result<T> = std::result::Result<T, CtapError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(CtapError(msg.into()))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub rk: Option<bool>,
    pub up: Option<bool>,
    pub uv: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MakeCredential {
    pub request: PlatformCreateRequest,
    pub options: Options,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetAssertion {
    pub request: PlatformGetRequest,
    pub options: Options,
}

/// Parses the top-level map. A leading CTAP command byte (0x01 / 0x02) is tolerated.
fn top_level(bytes: &[u8], command: u8) -> Result<Vec<(Value, Value)>> {
    let body = match bytes.first() {
        Some(&b) if b == command => &bytes[1..],
        _ => bytes,
    };
    let value: Value =
        ciborium::de::from_reader(body).map_err(|e| CtapError(format!("CBOR: {e}")))?;
    match value {
        Value::Map(entries) => Ok(entries),
        _ => err("not a CBOR map"),
    }
}

fn int_key(key: &Value) -> Option<i128> {
    key.as_integer().map(i128::from)
}

fn get(map: &[(Value, Value)], key: i128) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| int_key(k) == Some(key))
        .map(|(_, v)| v)
}

fn text_field<'a>(map: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(name))
        .map(|(_, v)| v)
}

fn bytes(value: Option<&Value>, what: &str) -> Result<Vec<u8>> {
    match value {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        Some(_) => err(format!("{what} must be a byte string")),
        None => err(format!("{what} is missing")),
    }
}

fn opt_text(value: Option<&Value>, what: &str) -> Result<Option<String>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Text(t)) => Ok(Some(t.clone())),
        Some(_) => err(format!("{what} must be a text string")),
    }
}

fn map_of<'a>(value: Option<&'a Value>, what: &str) -> Result<&'a [(Value, Value)]> {
    match value {
        Some(Value::Map(m)) => Ok(m),
        Some(_) => err(format!("{what} must be a map")),
        None => err(format!("{what} is missing")),
    }
}

fn descriptor_ids(value: Option<&Value>, what: &str) -> Result<Vec<Vec<u8>>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Value::Array(list) = value else {
        return err(format!("{what} must be an array"));
    };
    let mut ids = Vec::new();
    for entry in list {
        let Value::Map(m) = entry else {
            return err(format!("{what} entries must be maps"));
        };
        if text_field(m, "type").and_then(Value::as_text) != Some("public-key") {
            continue;
        }
        ids.push(bytes(text_field(m, "id"), &format!("{what}.id"))?);
    }
    Ok(ids)
}

fn options(value: Option<&Value>) -> Result<Options> {
    let Some(value) = value else {
        return Ok(Options::default());
    };
    let Value::Map(m) = value else {
        return err("options must be a map");
    };
    let flag = |name: &str| text_field(m, name).and_then(Value::as_bool);
    Ok(Options {
        rk: flag("rk"),
        up: flag("up"),
        uv: flag("uv"),
    })
}

/// `authenticatorMakeCredential` (CTAP 2.1 §6.1): 1 clientDataHash, 2 rp, 3 user,
/// 4 pubKeyCredParams, 5 excludeList, 7 options. Extensions and PIN/UV auth are ignored.
pub fn parse_make_credential(encoded: &[u8]) -> Result<MakeCredential> {
    let map = top_level(encoded, 0x01)?;
    let client_data_hash = bytes(get(&map, 1), "clientDataHash")?;
    let rp = map_of(get(&map, 2), "rp")?;
    let rp_id = opt_text(text_field(rp, "id"), "rp.id")?
        .filter(|id| !id.is_empty())
        .ok_or_else(|| CtapError("rp.id is missing".into()))?;
    let rp_name = opt_text(text_field(rp, "name"), "rp.name")?;
    let user = map_of(get(&map, 3), "user")?;
    let user_handle = bytes(text_field(user, "id"), "user.id")?;
    let user_name = opt_text(text_field(user, "name"), "user.name")?.unwrap_or_default();
    let user_display_name = opt_text(text_field(user, "displayName"), "user.displayName")?;
    let Some(Value::Array(params)) = get(&map, 4) else {
        return err("pubKeyCredParams is missing");
    };
    let mut algorithms = Vec::new();
    for param in params {
        let Value::Map(p) = param else {
            return err("pubKeyCredParams entries must be maps");
        };
        if text_field(p, "type").and_then(Value::as_text) != Some("public-key") {
            continue;
        }
        match text_field(p, "alg").and_then(Value::as_integer) {
            Some(alg) => algorithms.push(
                i64::try_from(i128::from(alg)).map_err(|_| CtapError("alg out of range".into()))?,
            ),
            None => return err("pubKeyCredParams.alg is missing"),
        }
    }
    if algorithms.is_empty() {
        // An empty list after filtering means no algorithm we could even consider.
        return err("no public-key algorithms offered");
    }
    Ok(MakeCredential {
        request: PlatformCreateRequest {
            rp_id,
            rp_name,
            user_handle,
            user_name,
            user_display_name,
            client_data_hash,
            algorithms,
            exclude_credentials: descriptor_ids(get(&map, 5), "excludeList")?,
        },
        options: options(get(&map, 7))?,
    })
}

/// `authenticatorGetAssertion` (CTAP 2.1 §6.2): 1 rpId, 2 clientDataHash, 3 allowList,
/// 5 options. Extensions and PIN/UV auth are ignored.
pub fn parse_get_assertion(encoded: &[u8]) -> Result<GetAssertion> {
    let map = top_level(encoded, 0x02)?;
    let rp_id = opt_text(get(&map, 1), "rpId")?
        .filter(|id| !id.is_empty())
        .ok_or_else(|| CtapError("rpId is missing".into()))?;
    Ok(GetAssertion {
        request: PlatformGetRequest {
            rp_id,
            client_data_hash: bytes(get(&map, 2), "clientDataHash")?,
            allow_credentials: descriptor_ids(get(&map, 3), "allowList")?,
        },
        options: options(get(&map, 5))?,
    })
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("CBOR encoding into a Vec cannot fail");
    out
}

fn int(n: i64) -> Value {
    Value::Integer(n.into())
}

fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

/// `authenticatorMakeCredential` response with `none` attestation: {1: fmt, 2: authData, 3: attStmt}.
pub fn encode_make_credential_response(authenticator_data: &[u8]) -> Vec<u8> {
    encode(&Value::Map(vec![
        (int(1), text("none")),
        (int(2), Value::Bytes(authenticator_data.to_vec())),
        (int(3), Value::Map(Vec::new())),
    ]))
}

/// `authenticatorGetAssertion` response: {1: credential, 2: authData, 3: signature, 4: user}.
/// `user` carries name and displayName because the user was verified (CTAP 2.1 §6.2.2).
pub fn encode_get_assertion_response(assertion: &PlatformAssertion) -> Vec<u8> {
    let credential = Value::Map(vec![
        (text("id"), Value::Bytes(assertion.credential_id.clone())),
        (text("type"), text("public-key")),
    ]);
    let mut user = vec![(text("id"), Value::Bytes(assertion.user_handle.clone()))];
    if !assertion.user_name.is_empty() {
        user.push((text("name"), text(&assertion.user_name)));
    }
    if !assertion.user_display_name.is_empty() {
        user.push((text("displayName"), text(&assertion.user_display_name)));
    }
    encode(&Value::Map(vec![
        (int(1), credential),
        (int(2), Value::Bytes(assertion.authenticator_data.clone())),
        (int(3), Value::Bytes(assertion.signature.clone())),
        (int(4), Value::Map(user)),
    ]))
}

/// `authenticatorGetInfo` (CTAP 2.1 §6.4) describing Pass: FIDO 2.0/2.1, the AAGUID, resident
/// keys + user presence + user verification, `internal` transport, ES256 only. No extensions.
pub fn authenticator_info(aaguid: &[u8; 16]) -> Vec<u8> {
    encode(&Value::Map(vec![
        (
            int(1),
            Value::Array(vec![text("FIDO_2_0"), text("FIDO_2_1")]),
        ),
        (int(3), Value::Bytes(aaguid.to_vec())),
        (
            int(4),
            Value::Map(vec![
                (text("rk"), Value::Bool(true)),
                (text("up"), Value::Bool(true)),
                (text("uv"), Value::Bool(true)),
            ]),
        ),
        (int(9), Value::Array(vec![text("internal")])),
        (
            int(10),
            Value::Array(vec![Value::Map(vec![
                (text("alg"), int(-7)),
                (text("type"), text("public-key")),
            ])]),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// {1: h'11'*32, 2: {"id": "example.com", "name": "Example"},
    ///  3: {"id": h'0102', "name": "alice", "displayName": "Alice"},
    ///  4: [{"alg": -7, "type": "public-key"}]}
    /// (`WebAuthNDecodeMakeCredentialRequest` accepts exactly this and rejects it with a 0x01 prefix.)
    const MAKE_CREDENTIAL: &str =
        "a4 01 5820 1111111111111111111111111111111111111111111111111111111111111111
        02 a2 626964 6b6578616d706c652e636f6d 646e616d65 674578616d706c65
        03 a3 626964 420102 646e616d65 65616c696365 6b646973706c61794e616d65 65416c696365
        04 81 a2 63616c67 26 6474797065 6a7075626c69632d6b6579";

    /// {1: "example.com", 2: h'22'*32, 3: [{"id": h'0a0b', "type": "public-key"}],
    ///  5: {"up": true, "uv": true}}
    const GET_ASSERTION: &str = "a4 01 6b6578616d706c652e636f6d
        02 5820 2222222222222222222222222222222222222222222222222222222222222222
        03 81 a2 626964 420a0b 6474797065 6a7075626c69632d6b6579
        05 a2 627570 f5 627576 f5";

    #[test]
    fn parses_make_credential() {
        let mc = parse_make_credential(&unhex(MAKE_CREDENTIAL)).unwrap();
        let r = &mc.request;
        assert_eq!(r.client_data_hash, vec![0x11; 32]);
        assert_eq!(r.rp_id, "example.com");
        assert_eq!(r.rp_name.as_deref(), Some("Example"));
        assert_eq!(r.user_handle, [1, 2]);
        assert_eq!(r.user_name, "alice");
        assert_eq!(r.user_display_name.as_deref(), Some("Alice"));
        assert_eq!(r.algorithms, [-7]);
        assert!(r.exclude_credentials.is_empty());
        assert_eq!(mc.options, Options::default());

        let mut prefixed = vec![0x01];
        prefixed.extend(unhex(MAKE_CREDENTIAL));
        assert_eq!(parse_make_credential(&prefixed).unwrap(), mc);
    }

    #[test]
    fn make_credential_with_exclude_list_and_options() {
        let value = Value::Map(vec![
            (int(1), Value::Bytes(vec![3; 32])),
            (
                int(2),
                Value::Map(vec![(text("id"), text("login.example.org"))]),
            ),
            (
                int(3),
                Value::Map(vec![(text("id"), Value::Bytes(vec![9; 16]))]),
            ),
            (
                int(4),
                Value::Array(vec![
                    Value::Map(vec![
                        (text("alg"), int(-8)),
                        (text("type"), text("public-key")),
                    ]),
                    Value::Map(vec![
                        (text("alg"), int(-7)),
                        (text("type"), text("public-key")),
                    ]),
                    Value::Map(vec![
                        (text("alg"), int(-7)),
                        (text("type"), text("future-type")),
                    ]),
                ]),
            ),
            (
                int(5),
                Value::Array(vec![Value::Map(vec![
                    (text("id"), Value::Bytes(vec![0xaa, 0xbb])),
                    (text("type"), text("public-key")),
                ])]),
            ),
            (int(6), Value::Map(vec![(text("credProtect"), int(2))])),
            (
                int(7),
                Value::Map(vec![
                    (text("rk"), Value::Bool(true)),
                    (text("uv"), Value::Bool(false)),
                ]),
            ),
        ]);
        let mc = parse_make_credential(&encode(&value)).unwrap();
        assert_eq!(mc.request.rp_id, "login.example.org");
        assert_eq!(mc.request.rp_name, None);
        assert_eq!(mc.request.user_name, "");
        assert_eq!(mc.request.user_display_name, None);
        assert_eq!(mc.request.algorithms, [-8, -7]);
        assert_eq!(mc.request.exclude_credentials, [vec![0xaa, 0xbb]]);
        assert_eq!(
            mc.options,
            Options {
                rk: Some(true),
                up: None,
                uv: Some(false)
            }
        );
    }

    #[test]
    fn rejects_malformed_make_credential() {
        assert!(parse_make_credential(&[]).is_err());
        assert!(parse_make_credential(&[0x80]).is_err());
        let no_hash = Value::Map(vec![
            (int(2), Value::Map(vec![(text("id"), text("a.com"))])),
            (
                int(3),
                Value::Map(vec![(text("id"), Value::Bytes(vec![1]))]),
            ),
            (int(4), Value::Array(vec![])),
        ]);
        assert!(parse_make_credential(&encode(&no_hash)).is_err());
        let bad_user = Value::Map(vec![
            (int(1), Value::Bytes(vec![0; 32])),
            (int(2), Value::Map(vec![(text("id"), text("a.com"))])),
            (int(3), Value::Map(vec![(text("id"), text("not bytes"))])),
            (
                int(4),
                Value::Array(vec![Value::Map(vec![
                    (text("alg"), int(-7)),
                    (text("type"), text("public-key")),
                ])]),
            ),
        ]);
        assert!(parse_make_credential(&encode(&bad_user)).is_err());
    }

    #[test]
    fn parses_get_assertion() {
        let ga = parse_get_assertion(&unhex(GET_ASSERTION)).unwrap();
        assert_eq!(ga.request.rp_id, "example.com");
        assert_eq!(ga.request.client_data_hash, vec![0x22; 32]);
        assert_eq!(ga.request.allow_credentials, [vec![0x0a, 0x0b]]);
        assert_eq!(
            ga.options,
            Options {
                rk: None,
                up: Some(true),
                uv: Some(true)
            }
        );
        let value = Value::Map(vec![
            (int(1), text("example.com")),
            (int(2), Value::Bytes(vec![0; 32])),
        ]);
        let ga = parse_get_assertion(&encode(&value)).unwrap();
        assert!(ga.request.allow_credentials.is_empty());
        assert!(parse_get_assertion(&encode(&Value::Map(vec![(int(1), text("a.com"))]))).is_err());
    }

    #[test]
    fn make_credential_response_matches_windows_encoder() {
        let auth_data = vec![0xad; 37];
        assert_eq!(
            encode_make_credential_response(&auth_data),
            unhex(
                "a3 01 646e6f6e65 02 5825 adadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadad 03 a0"
            )
        );
    }

    #[test]
    fn get_assertion_response_matches_windows_encoder() {
        let assertion = PlatformAssertion {
            credential_id: vec![0x0a, 0x0b],
            authenticator_data: vec![0xad; 37],
            signature: vec![0x30, 0x02, 0x05, 0x00],
            user_handle: vec![1, 2],
            user_name: "alice".into(),
            user_display_name: "Alice".into(),
        };
        assert_eq!(
            encode_get_assertion_response(&assertion),
            unhex(
                "a4 01 a2 626964 420a0b 6474797065 6a7075626c69632d6b6579
                 02 5825 adadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadad
                 03 44 30020500
                 04 a3 626964 420102 646e616d65 65616c696365 6b646973706c61794e616d65 65416c696365"
            )
        );
        let anonymous = PlatformAssertion {
            user_name: String::new(),
            user_display_name: String::new(),
            ..assertion
        };
        let decoded: Value =
            ciborium::de::from_reader(&encode_get_assertion_response(&anonymous)[..]).unwrap();
        let user = get(decoded.as_map().unwrap(), 4).unwrap().as_map().unwrap();
        assert_eq!(user.len(), 1);
    }

    #[test]
    fn authenticator_info_describes_pass() {
        let info = authenticator_info(&pass_core::AAGUID);
        let value: Value = ciborium::de::from_reader(&info[..]).unwrap();
        let map = value.as_map().unwrap();
        assert_eq!(
            get(map, 3).unwrap().as_bytes().unwrap(),
            &pass_core::AAGUID.to_vec()
        );
        let versions: Vec<&str> = get(map, 1)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_text)
            .collect();
        assert_eq!(versions, ["FIDO_2_0", "FIDO_2_1"]);
        let opts = get(map, 4).unwrap().as_map().unwrap();
        assert_eq!(text_field(opts, "rk").and_then(Value::as_bool), Some(true));
        assert_eq!(text_field(opts, "uv").and_then(Value::as_bool), Some(true));
        // Canonical layout: same prefix as Microsoft's sample blob up to the AAGUID (minus key 2).
        assert_eq!(
            &info[..23],
            &unhex("a5 01 82 684649444f5f325f30 684649444f5f325f31 03 50")[..]
        );
    }
}
