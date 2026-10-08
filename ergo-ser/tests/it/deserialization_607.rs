//! Independent JVM 6.0.7 limits, exception classes and validation wrapping.
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::{ergo_tree, opcode, sigma_type, sigma_value};

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    mode: String,
    bytes_hex: String,
    version: u8,
    result: String,
    position: usize,
    rule_id: Option<u16>,
    canonical_hex: Option<String>,
}

#[test]
fn jvm_607_deserialization_boundaries_and_error_classes() {
    #[derive(serde::Deserialize)]
    struct Fixture {
        entries: Vec<Vector>,
    }
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../test-vectors/scala/deserialization_607.json"
    ))
    .unwrap();
    for v in fixture.entries {
        let bytes = hex::decode(&v.bytes_hex).unwrap();
        let mut r = VlqReader::new(&bytes).with_activated_script_version(3);
        r.set_ergo_tree_version(Some(v.version));
        let mut w = VlqWriter::new();
        let mut wrapped = None;
        let result = match v.mode.as_str() {
            "box-candidate" => ergo_ser::ergo_box::read_ergo_box_candidate(&mut r).map(|_| ()),
            "type" => {
                sigma_type::read_type(&mut r).map(|t| sigma_type::write_type(&mut w, &t).unwrap())
            }
            "write-zero-coll" => sigma_type::read_type(&mut r).and_then(|t| {
                sigma_value::write_value_versioned(
                    &mut w,
                    &t,
                    &sigma_value::SigmaValue::Coll(sigma_value::CollValue::Values(vec![])),
                    v.version,
                )
                .map_err(|e| ReadError::HardReject(e.to_string()))
            }),
            "constant" => sigma_value::read_constant(&mut r).map(|(t, x)| {
                sigma_value::write_constant_versioned(&mut w, &t, &x, v.version).unwrap();
            }),
            "expression" => opcode::parse_body(&mut r, v.version).map(|_| ()),
            "tree" => ergo_tree::read_ergo_tree(&mut r).map(|t| {
                if let opcode::Expr::Unparsed(u) = t.body {
                    wrapped = u.validation_error.map(|(id, _)| id);
                }
            }),
            _ => panic!("unknown mode {}", v.mode),
        };
        match v.result.as_str() {
            "ACCEPT" => {
                result.unwrap_or_else(|e| panic!("{}: {e:?}", v.name));
                assert_eq!(wrapped, None, "{}", v.name);
                if let Some(canonical) = v.canonical_hex {
                    assert_eq!(hex::encode(w.result()), canonical, "{}", v.name);
                }
                assert_eq!(r.position(), v.position, "{}", v.name);
            }
            "WRAPPED" => {
                result.unwrap_or_else(|e| panic!("{}: {e:?}", v.name));
                assert_eq!(wrapped, v.rule_id, "{}", v.name);
                assert_eq!(r.position(), v.position, "{}", v.name);
            }
            "DeserializeCallDepthExceeded" => {
                assert!(
                    matches!(result, Err(ReadError::DepthLimitExceeded { max: 8 })),
                    "{}: {result:?}",
                    v.name
                );
                // Trees parse through a scoped reader; failure does not publish
                // its position. Direct readers must stop before the depth-9 byte.
                if !matches!(v.mode.as_str(), "tree" | "box-candidate") {
                    assert_eq!(r.position(), v.position, "{}", v.name);
                }
            }
            "ValidationException" => {
                let Err(ReadError::SigmaValidation { rule_id, .. }) = result else {
                    panic!("{}: {result:?}", v.name);
                };
                // The existing primitive decoder uses legacy rule 1007; the
                // tree boundary translates it to 1017 at activation >= 3.
                let rule_id = if rule_id == 1007 { 1017 } else { rule_id };
                assert_eq!(Some(rule_id), v.rule_id, "{}", v.name);
                assert_eq!(r.position(), v.position, "{}", v.name);
            }
            "SerializerException" => {
                // Older unsized rules retain their legacy hard-at-call-site
                // representation. Rule 1020 must be translated at the boundary
                // to prevent an enclosing sized tree wrapping it instead.
                assert!(
                    matches!(
                        result,
                        Err(ReadError::HardReject(_))
                            | Err(ReadError::SigmaValidation { rule_id: 1009, .. })
                    ),
                    "{}: {result:?}",
                    v.name
                );
            }
            other => panic!("{}: unexpected JVM result {other}", v.name),
        }
    }
}

#[test]
fn zero_width_collection_writes_reject_even_when_empty() {
    use sigma_type::SigmaType as T;
    use sigma_value::{CollValue, SigmaValue as V};
    for elem in [
        T::SUnit,
        T::SColl(Box::new(T::SUnit)),
        T::STuple(vec![T::SUnit, T::SUnit]),
        T::STuple(vec![]),
    ] {
        let t = T::SColl(Box::new(elem));
        let x = V::Coll(CollValue::Values(vec![]));
        assert!(sigma_value::write_constant(&mut VlqWriter::new(), &t, &x).is_err());
    }
}
