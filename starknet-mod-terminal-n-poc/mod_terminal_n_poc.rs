use std::fs::read;

use cairo_air::verifier::verify_cairo;
use cairo_vm::cairo_run::{CairoRunConfig, cairo_run_program_with_initial_scope};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::program::Program;
use stwo::core::fri::FriConfig;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTraceVariant;
use stwo_cairo_dev_utils::utils::get_compiled_cairo_program_path;
use stwo_cairo_dev_utils::vm_utils::{ProgramType, run_and_adapt};
use stwo_cairo_prover::prover::{
    ChannelHash, LiftingSizePolicy, ProverParameters, prove_cairo,
};

#[test]
fn poc_add_mod_terminal_n_is_not_constrained_by_air() {
    let program_path = get_compiled_cairo_program_path("mod_terminal_n");

    // proof_mode deliberately does not run Cairo VM's secure-run checks. This is the normal
    // adapter path used to obtain a ProverInput for STWO.
    let input = run_and_adapt(
        &program_path,
        ProgramType::Json,
        LayoutName::all_cairo_stwo,
        None,
    )
    .expect("proof-mode VM execution and adaptation");

    let segment = input
        .builtin_segments
        .add_mod_builtin
        .expect("add_mod segment must be present");
    let n_instances = (segment.stop_ptr - segment.begin_addr) / 7;
    assert_eq!(n_instances, 16, "PoC must have exactly 16 real instances and no builtin padding");

    // n is the seventh cell of each ModBuiltin instance. The last public instance deliberately
    // has n=2 although batch_size=1.
    let last_n_addr = segment.stop_ptr - 1;
    let last_n = input.memory.get(last_n_addr as u32).as_small();
    println!("ADD_MOD_INSTANCES={n_instances}");
    println!("LAST_ADD_MOD_N={last_n}");
    assert_eq!(last_n, 2);

    // Use the production Cairo prover security target: 26 PoW bits + 70 FRI queries at blowup 2
    // = 96 bits. CanonicalSmall only reduces the fixed preprocessed-table footprint; the AddMod
    // AIR component and the malicious execution are unchanged.
    let production_fri = FriConfig::new(26, 0, 1, 70, 1);
    assert_eq!(production_fri.security_bits(), 96);
    println!("FRI_SECURITY_BITS={}", production_fri.security_bits());
    let prover_params = ProverParameters {
        channel_hash: ChannelHash::Blake2s,
        channel_salt: 0,
        fri_config: production_fri,
        preprocessed_trace: PreProcessedTraceVariant::CanonicalSmall,
        store_polynomials_coefficients: false,
        include_all_preprocessed_columns: false,
        opt_n_id_to_big_components: None,
        lifting_size_policy: LiftingSizePolicy::Auto,
    };
    let proof = prove_cairo::<Blake2sMerkleChannel>(input, prover_params)
        .expect("STWO should produce the malicious proof if terminal n is unconstrained");
    verify_cairo::<Blake2sMerkleChannel>(proof.into())
        .expect("unmodified sharp-8.0 verifier accepted malicious terminal n");
    println!("STWO_FULL_STARK_ACCEPTED_TERMINAL_N_2_AT_96_BITS");

    // Run the identical compiled Cairo program with Cairo VM secure-run checks enabled.
    // The modulo builtin's production security check requires final n == batch_size (1).
    let program_bytes = read(&program_path).expect("read compiled program");
    let program = Program::from_bytes(&program_bytes, Some("main")).expect("parse compiled program");
    let config = CairoRunConfig {
        trace_enabled: true,
        relocate_mem: false,
        relocate_trace: false,
        layout: LayoutName::all_cairo_stwo,
        proof_mode: true,
        fill_holes: true,
        secure_run: Some(true),
        disable_trace_padding: true,
        allow_missing_builtins: None,
        dynamic_layout_params: None,
        entrypoint: "main",
    };
    let mut exec_scopes = ExecutionScopes::new();
    exec_scopes.insert_value("program_object", program.clone());
    let mut hint_processor = BuiltinHintProcessor::new_empty();
    let err = match cairo_run_program_with_initial_scope(
        &program,
        &config,
        &mut hint_processor,
        exec_scopes,
    ) {
        Ok(_) => panic!("secure Cairo VM unexpectedly accepted terminal n=2"),
        Err(err) => err,
    };

    let err_text = format!("{err:?}");
    println!("CAIRO_VM_SECURE_REJECT={err_text}");
    assert!(
        err_text.contains("ModBuiltinSecurityCheck")
            || err_text.contains("prev_inputs.n != batch_size"),
        "unexpected secure-run error: {err_text}"
    );
    println!("MOD_TERMINAL_N_FINAL_POC_ALL_PASSED");
}
