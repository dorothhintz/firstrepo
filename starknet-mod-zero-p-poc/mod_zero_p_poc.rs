use std::fs::read;
use std::panic::{AssertUnwindSafe, catch_unwind};

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
use stwo_cairo_prover::prover::{ChannelHash, LiftingSizePolicy, ProverParameters, prove_cairo};

#[test]
fn poc_add_mod_zero_modulus_is_accepted_by_air() {
    let program_path = get_compiled_cairo_program_path("mod_zero_p");

    // Normal STWO proof-mode execution path. secure_run is disabled in proof mode.
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
    assert_eq!(n_instances, 16, "PoC must have exactly 16 real AddMod instances");

    // p.d0 is the first cell of every ModBuiltin instance. All four p limbs are zero.
    let first_p0 = input.memory.get(segment.begin_addr as u32).as_small();
    let first_p1 = input.memory.get((segment.begin_addr + 1) as u32).as_small();
    let first_p2 = input.memory.get((segment.begin_addr + 2) as u32).as_small();
    let first_p3 = input.memory.get((segment.begin_addr + 3) as u32).as_small();
    println!("ADD_MOD_INSTANCES={n_instances}");
    println!("MODULUS_LIMBS={first_p0},{first_p1},{first_p2},{first_p3}");
    assert_eq!([first_p0, first_p1, first_p2, first_p3], [0, 0, 0, 0]);

    // Production 96-bit FRI target.
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
        .expect("STWO prover should produce p=0 proof if AIR permits the degenerate modulus");
    verify_cairo::<Blake2sMerkleChannel>(proof.into())
        .expect("unmodified sharp-8.0 verifier accepted p=0 AddMod proof");
    println!("STWO_FULL_STARK_ACCEPTED_ADD_MOD_P_ZERO_AT_96_BITS");

    // The identical compiled Cairo program under secure VM checks must not be accepted.
    // Cairo VM validates each ModBuiltin operation by computing (... mod p), for which p=0
    // is invalid. Catch either a structured error or the BigUint division-by-zero panic.
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
    let secure_outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.insert_value("program_object", program.clone());
        let mut hint_processor = BuiltinHintProcessor::new_empty();
        cairo_run_program_with_initial_scope(
            &program,
            &config,
            &mut hint_processor,
            exec_scopes,
        )
    }));

    match secure_outcome {
        Ok(Ok(_)) => panic!("secure Cairo VM unexpectedly accepted AddMod modulus p=0"),
        Ok(Err(err)) => println!("CAIRO_VM_SECURE_REJECT_P_ZERO={err:?}"),
        Err(_) => println!("CAIRO_VM_SECURE_PANIC_P_ZERO"),
    }
    println!("MOD_ZERO_P_POC_ALL_PASSED");
}
