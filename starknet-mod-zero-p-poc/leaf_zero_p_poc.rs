use std::path::PathBuf;

use leaf_prover::prove_leaf::prove_leaf_from_files;

#[test]
fn poc_canonical_small_leaf_registry_accepts_zero_modulus_task() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = crate_dir.join("../..");

    let task_path = repo_root.join("test_data/mod_zero_p/compiled.json");
    assert!(task_path.exists(), "malicious p=0 task must be compiled before the test");

    let leaf_program = crate_dir.join("test_data/leaf_simple_bootloader_compiled.json");
    let registry = crate_dir.join("test_data/circuit_registry.json");

    let tmp = tempfile::tempdir().unwrap();
    let dump_path = tmp.path().join("leaf_preimage.json");
    let input_path = tmp.path().join("leaf_bl_input.json");

    // Same shape as the repository's golden leaf E2E, but the RunProgramTask is our
    // AddMod program whose modulus p is zero. The leaf simple bootloader executes tasks
    // in the proof-mode pipeline used by leaf_prover.
    let input = serde_json::json!({
        "tasks": [{
            "type": "RunProgramTask",
            "path": task_path.to_str().unwrap(),
            "program_hash_function": "blake"
        }],
        "fact_topologies_path": null,
        "single_page": true,
        "output_preimage_dump_path": dump_path.to_str().unwrap()
    });
    std::fs::write(&input_path, serde_json::to_string_pretty(&input).unwrap()).unwrap();

    let leaf = prove_leaf_from_files(&leaf_program, &Some(input_path), &registry);

    println!("RECURSIVE_LEAF_ZERO_P_CIRCUIT_HASH={:?}", leaf.circuit_hash.0);
    println!("RECURSIVE_LEAF_ZERO_P_PREPROCESSED_ROOT={:?}", leaf.circuit_preprocessed_root.0);
    println!("RECURSIVE_LEAF_ZERO_P_PROOF_BYTES={}", leaf.proof.len());
    assert!(!leaf.proof.is_empty());
    assert!(dump_path.exists(), "leaf bootloader must have produced its output preimage");

    // Reaching here means leaf_prover has already:
    // 1. produced the Cairo STARK for the bootloader execution containing the p=0 task,
    // 2. built and evaluated the Cairo-verifier circuit and asserted is_circuit_valid(),
    // 3. proved that verifier circuit, and
    // 4. asserted its circuit_hash equals the canonical-small registry leaf entry.
    println!("CANONICAL_SMALL_REGISTRY_LEAF_ACCEPTED_ZERO_MODULUS_TASK");
}
