#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl,
    crypto::bls12_381::{Fr, G1Affine, G2Affine, G1_SERIALIZED_SIZE, G2_SERIALIZED_SIZE},
    symbol_short, vec, Bytes, Env, Symbol, Vec, U256,
};

const VK_KEY: Symbol = symbol_short!("VK");

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum VerifierError {
    MalformedVerifyingKey = 1,
    VerificationKeyNotSet = 2,
    MalformedProof = 3,
    MalformedPublicSignals = 4,
}

#[derive(Clone)]
struct VerificationKey {
    alpha: G1Affine,
    beta: G2Affine,
    gamma: G2Affine,
    delta: G2Affine,
    ic: Vec<G1Affine>,
}

#[derive(Clone)]
struct Proof {
    a: G1Affine,
    b: G2Affine,
    c: G1Affine,
}

#[derive(Clone)]
struct PublicSignals {
    pub_signals: Vec<Fr>,
}

fn take<const N: usize>(
    bytes: &Bytes,
    pos: &mut u32,
    err: VerifierError,
) -> Result<[u8; N], VerifierError> {
    let end = pos.checked_add(N as u32).ok_or(err)?;
    if end > bytes.len() {
        return Err(err);
    }

    let mut arr = [0u8; N];
    bytes.slice(*pos..end).copy_into_slice(&mut arr);
    *pos = end;
    Ok(arr)
}

impl VerificationKey {
    fn from_bytes(env: &Env, bytes: &Bytes) -> Result<Self, VerifierError> {
        let mut pos = 0u32;

        let alpha = G1Affine::from_array(
            env,
            &take::<G1_SERIALIZED_SIZE>(bytes, &mut pos, VerifierError::MalformedVerifyingKey)?,
        );
        let beta = G2Affine::from_array(
            env,
            &take::<G2_SERIALIZED_SIZE>(bytes, &mut pos, VerifierError::MalformedVerifyingKey)?,
        );
        let gamma = G2Affine::from_array(
            env,
            &take::<G2_SERIALIZED_SIZE>(bytes, &mut pos, VerifierError::MalformedVerifyingKey)?,
        );
        let delta = G2Affine::from_array(
            env,
            &take::<G2_SERIALIZED_SIZE>(bytes, &mut pos, VerifierError::MalformedVerifyingKey)?,
        );

        let ic_len_bytes = take::<4>(bytes, &mut pos, VerifierError::MalformedVerifyingKey)?;
        let ic_len = u32::from_be_bytes(ic_len_bytes);
        let mut ic = Vec::new(env);

        for _ in 0..ic_len {
            let g1 = G1Affine::from_array(
                env,
                &take::<G1_SERIALIZED_SIZE>(bytes, &mut pos, VerifierError::MalformedVerifyingKey)?,
            );
            ic.push_back(g1);
        }

        if pos != bytes.len() || ic_len == 0 {
            return Err(VerifierError::MalformedVerifyingKey);
        }

        Ok(Self {
            alpha,
            beta,
            gamma,
            delta,
            ic,
        })
    }
}

impl Proof {
    fn from_bytes(env: &Env, bytes: &Bytes) -> Result<Self, VerifierError> {
        let mut pos = 0u32;

        let a = G1Affine::from_array(
            env,
            &take::<G1_SERIALIZED_SIZE>(bytes, &mut pos, VerifierError::MalformedProof)?,
        );
        let b = G2Affine::from_array(
            env,
            &take::<G2_SERIALIZED_SIZE>(bytes, &mut pos, VerifierError::MalformedProof)?,
        );
        let c = G1Affine::from_array(
            env,
            &take::<G1_SERIALIZED_SIZE>(bytes, &mut pos, VerifierError::MalformedProof)?,
        );

        if pos != bytes.len() {
            return Err(VerifierError::MalformedProof);
        }

        Ok(Self { a, b, c })
    }
}

impl PublicSignals {
    fn from_bytes(env: &Env, bytes: &Bytes) -> Result<Self, VerifierError> {
        let mut pos = 0u32;

        let len_bytes = take::<4>(bytes, &mut pos, VerifierError::MalformedPublicSignals)?;
        let len = u32::from_be_bytes(len_bytes);
        let mut pub_signals = Vec::new(env);

        for _ in 0..len {
            let arr = take::<32>(bytes, &mut pos, VerifierError::MalformedPublicSignals)?;
            let u256 = U256::from_be_bytes(env, &Bytes::from_array(env, &arr));
            pub_signals.push_back(Fr::from_u256(u256));
        }

        if pos != bytes.len() {
            return Err(VerifierError::MalformedPublicSignals);
        }

        Ok(Self { pub_signals })
    }
}

fn verify_proof(
    env: &Env,
    vk: VerificationKey,
    proof: Proof,
    pub_signals: Vec<Fr>,
) -> Result<bool, VerifierError> {
    if pub_signals.len() + 1 != vk.ic.len() {
        return Err(VerifierError::MalformedVerifyingKey);
    }

    let bls = env.crypto().bls12_381();

    let mut vk_x = vk.ic.get(0).unwrap();
    for (s, v) in pub_signals.iter().zip(vk.ic.iter().skip(1)) {
        let prod = bls.g1_mul(&v, &s);
        vk_x = bls.g1_add(&vk_x, &prod);
    }

    let neg_a = -proof.a;
    let vp1 = vec![env, neg_a, vk.alpha, vk_x, proof.c];
    let vp2 = vec![env, proof.b, vk.beta, vk.gamma, vk.delta];

    Ok(bls.pairing_check(vp1, vp2))
}

#[contract]
pub struct Groth16VerifierContract;

#[contractimpl]
impl Groth16VerifierContract {
    pub fn set_vk(env: Env, vk_bytes: Bytes) -> Result<(), VerifierError> {
        // Parse once here so malformed keys fail fast and cannot be stored.
        let _vk = VerificationKey::from_bytes(&env, &vk_bytes)?;
        env.storage().instance().set(&VK_KEY, &vk_bytes);
        Ok(())
    }

    pub fn verify(
        env: Env,
        proof_bytes: Bytes,
        pub_signals_bytes: Bytes,
    ) -> Result<bool, VerifierError> {
        let vk_bytes: Bytes = env
            .storage()
            .instance()
            .get(&VK_KEY)
            .ok_or(VerifierError::VerificationKeyNotSet)?;

        let vk = VerificationKey::from_bytes(&env, &vk_bytes)?;
        let proof = Proof::from_bytes(&env, &proof_bytes)?;
        let pub_signals = PublicSignals::from_bytes(&env, &pub_signals_bytes)?;

        verify_proof(&env, vk, proof, pub_signals.pub_signals)
    }
}
