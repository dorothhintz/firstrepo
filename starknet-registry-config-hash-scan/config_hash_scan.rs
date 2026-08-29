use std::path::Path;

use circuit_params::{CircuitBuilder, DUMMY_PREPROCESSED_ROOT, RegistryDefinition};
use circuit_cairo_verifier::utils::load_program;
use stwo::core::fri::FriConfig;

#[test]
fn scan_weaker_inner_cairo_configs_for_identical_leaf_topology() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let definition = RegistryDefinition::load(&repo_root, "production");
    let params = definition.cairo_params();
    let program = load_program(&definition.program);
    let trace_log_size = definition.min_trace_log_size;
    let base = params.fri_config;

    assert_eq!(trace_log_size, 25);
    assert_eq!(base.pow_bits, 26);
    assert_eq!(base.log_blowup_factor, 1);
    assert_eq!(base.n_queries, 70);
    assert_eq!(base.fold_step, 1);

    let build = |fri: FriConfig| {
        CircuitBuilder {
            preprocessed_trace: params.preprocessed_trace,
            program: program.clone(),
            cairo_fri_config: fri,
        }
        .build_context(trace_log_size, DUMMY_PREPROCESSED_ROOT.into())
    };

    let canonical = build(base);
    println!("BASE_N_VARS={}", canonical.circuit().n_vars);
    println!("BASE_ADD={}", canonical.circuit().add.len());
    println!("BASE_QM31_ROWS={}", canonical.circuit().n_qm31_ops_rows());

    let variants: [(&str, FriConfig); 8] = [
        ("pow25", FriConfig::new(25, 0, 1, 70, 1)),
        ("pow0", FriConfig::new(0, 0, 1, 70, 1)),
        ("queries69", FriConfig::new(26, 0, 1, 69, 1)),
        ("queries1", FriConfig::new(26, 0, 1, 1, 1)),
        ("fold2", FriConfig::new(26, 0, 1, 70, 2)),
        ("fold4", FriConfig::new(26, 0, 1, 70, 4)),
        ("last1", FriConfig::new(26, 1, 1, 70, 1)),
        ("blowup2", FriConfig::new(26, 0, 2, 35, 1)),
    ];

    let mut collisions = Vec::new();
    for (name, fri) in variants {
        let candidate = build(fri);
        let same = canonical.circuit() == candidate.circuit();
        println!(
            "VARIANT={name} security={} SAME_RAW_CIRCUIT={} n_vars={} add={} qm31_rows={}",
            fri.security_bits(),
            same,
            candidate.circuit().n_vars,
            candidate.circuit().add.len(),
            candidate.circuit().n_qm31_ops_rows(),
        );
        if same {
            collisions.push(name);
        }
    }

    println!("IDENTICAL_RAW_CIRCUIT_VARIANTS={collisions:?}");
    assert!(collisions.is_empty(), "registry identity collision candidates: {collisions:?}");
}
