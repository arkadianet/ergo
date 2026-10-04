//! Public numeric argument adaptation, including lifted BigInt constants.

use ergo_compiler::{node_tpe, typecheck, EnvValue, SType, ScriptEnv};

#[test]
fn numeric_constants_narrow_at_variable_argument_guards() {
    for value in [
        EnvValue::Byte(1),
        EnvValue::Short(1),
        EnvValue::Int(1),
        EnvValue::Long(1),
        EnvValue::BigInt("1".to_owned()),
    ] {
        let mut env = ScriptEnv::new();
        env.insert("id", value);
        for (source, expected) in [
            ("getVar[Int](id)", SType::SOption(Box::new(SType::SInt))),
            (
                "CONTEXT.getVarFromInput[Int](0, id)",
                SType::SOption(Box::new(SType::SInt)),
            ),
            ("executeFromVar[Int](id)", SType::SInt),
        ] {
            let result = typecheck(&env, source, 3).unwrap();
            assert_eq!(node_tpe(&result), &expected);
        }
    }
}

#[test]
fn bigint_variable_argument_out_of_range_returns_structured_error() {
    let mut env = ScriptEnv::new();
    env.insert("id", EnvValue::BigInt("128".to_owned()));
    for source in [
        "getVar[Int](id)",
        "CONTEXT.getVarFromInput[Int](0, id)",
        "executeFromVar[Int](id)",
    ] {
        assert!(typecheck(&env, source, 3).is_err(), "{source}");
    }
    env.insert("input", EnvValue::BigInt("32768".to_owned()));
    assert!(typecheck(&env, "CONTEXT.getVarFromInput[Int](input, 1)", 3).is_err());
}
