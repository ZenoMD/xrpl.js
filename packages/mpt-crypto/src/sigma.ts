/* eslint-disable max-lines, max-lines-per-function -- each builder is one cohesive WASM marshalling flow */
/**
 * Low-level XLS-96 proof components: the compact Send and ConvertBack sigma
 * proofs and the aggregated Bulletproof range proof, each over caller-chosen
 * inputs. The per-transaction builders in `proofs.ts` compose these internally
 * for fixed statements; these are for protocols (such as confidential lending)
 * that prove the same relations over other recipients or derived commitments.
 */
import {
  BLINDING_FACTOR_SIZE,
  CLAWBACK_PROOF_SIZE,
  CONTEXT_HASH_SIZE,
  CONVERT_BACK_SIGMA_PROOF_SIZE,
  DOUBLE_BULLETPROOF_SIZE,
  ELGAMAL_TOTAL_SIZE,
  PEDERSEN_COMMIT_SIZE,
  PRIVKEY_SIZE,
  PUBKEY_SIZE,
  SEND_SIGMA_PROOF_SIZE,
  SINGLE_BULLETPROOF_SIZE,
} from './constants'
import { bytesToHex, hexToBytes } from './hex'
import { assertUint64, rawParticipant, rawPedersenParams } from './internal'
import { Marshaller } from './marshal'
import { WasmModule } from './module'
import { withModule } from './runtime'
import { Participant, PedersenParams } from './types'

// sizeof(secp256k1_pubkey), an opaque 64-byte struct.
const PUBKEY_STRUCT_SIZE = 64
const U64_BYTES = 8
const SIZE_T_BYTES = 4
const POINTER_BYTES = 4
// secp256k1 calls return 1 on success / a valid proof.
const SECP_OK = 1
// The aggregated Bulletproof supports one or two values, as XLS-96 does.
const MAX_RANGE_VALUES = 2

/** The secp256k1 group order n. */
const CURVE_ORDER = BigInt(
  '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',
)

/**
 * Inputs for {@link getSendSigmaProof}: the XLS-96 Send sigma relation, proving
 * that every recipient ciphertext encrypts the value committed in
 * `amountCommitment` with one shared randomness, and that the prover owns the
 * balance described by `balanceParams`.
 */
export interface SendSigmaProofParams {
  /** The balance holder's 32-byte private key. */
  privateKey: string
  /** The balance holder's 33-byte public key. */
  publicKey: string
  /** The value the recipient ciphertexts encrypt. */
  amount: bigint
  /** The shared ElGamal randomness r, also the blinding factor of `amountCommitment`. */
  blindingFactor: string
  /** The recipients; their ciphertexts must all be encrypted with `blindingFactor`. */
  recipients: Participant[]
  /** The 33-byte Pedersen commitment `amount*G + r*H`. */
  amountCommitment: string
  /** The holder's balance witness. */
  balanceParams: PedersenParams
  /** The 32-byte transaction context hash. */
  contextHash: string
}

/** The public statement a {@link getSendSigmaProof} proof is verified against. */
export interface SendSigmaStatement {
  /** The balance holder's 33-byte public key. */
  publicKey: string
  /** The recipients. */
  recipients: Participant[]
  /** The 33-byte Pedersen commitment to the amount. */
  amountCommitment: string
  /** The 33-byte Pedersen commitment to the balance. */
  balanceCommitment: string
  /** The 66-byte ciphertext of the balance under `publicKey`. */
  balanceCiphertext: string
  /** The 32-byte transaction context hash. */
  contextHash: string
}

/**
 * Inputs for {@link getConvertBackSigmaProof}: the XLS-96 ConvertBack sigma
 * relation, proving that the holder of `privateKey` can decrypt
 * `balanceParams.ciphertext` and that `balanceParams.commitment` commits to
 * its value.
 */
export interface ConvertBackSigmaProofParams {
  /** The holder's 32-byte private key. */
  privateKey: string
  /** The holder's 33-byte public key. */
  publicKey: string
  /** The ciphertext, its decrypted value, and the commitment to that value. */
  balanceParams: PedersenParams
  /** The 32-byte transaction context hash. */
  contextHash: string
}

/** The public statement a {@link getConvertBackSigmaProof} proof is verified against. */
export interface ConvertBackSigmaStatement {
  /** The holder's 33-byte public key. */
  publicKey: string
  /** The 66-byte ciphertext under `publicKey`. */
  ciphertext: string
  /** The 33-byte Pedersen commitment to its value. */
  commitment: string
  /** The 32-byte transaction context hash. */
  contextHash: string
}

/**
 * Parse a 33-byte compressed point into a WASM `secp256k1_pubkey` struct.
 *
 * @param mod - The loaded WASM module.
 * @param marshaller - The call's marshaller.
 * @param point - The compressed point bytes.
 * @param label - A human-readable name used in error messages.
 * @returns A pointer to the parsed struct.
 * @throws If the point is not on the curve.
 */
// eslint-disable-next-line max-params -- the module and marshaller thread through every helper
function parsePoint(
  mod: WasmModule,
  marshaller: Marshaller,
  point: Uint8Array,
  label: string,
): number {
  const out = marshaller.alloc(PUBKEY_STRUCT_SIZE)
  const input = marshaller.allocBytes(point)
  if (
    mod._secp256k1_ec_pubkey_parse(
      mod._mpt_secp256k1_context(),
      out,
      input,
      point.length,
    ) !== SECP_OK
  ) {
    throw new Error(`mpt-crypto: ${label} is not a valid point`)
  }
  return out
}

/**
 * Parse a 66-byte ciphertext into two WASM `secp256k1_pubkey` structs.
 *
 * @param mod - The loaded WASM module.
 * @param marshaller - The call's marshaller.
 * @param ciphertext - The ciphertext bytes (`C1 || C2`).
 * @param label - A human-readable name used in error messages.
 * @returns Pointers to the parsed C1 and C2.
 * @throws If the ciphertext is malformed.
 */
// eslint-disable-next-line max-params -- the module and marshaller thread through every helper
function parseCiphertext(
  mod: WasmModule,
  marshaller: Marshaller,
  ciphertext: Uint8Array,
  label: string,
): [number, number] {
  const c1 = marshaller.alloc(PUBKEY_STRUCT_SIZE)
  const c2 = marshaller.alloc(PUBKEY_STRUCT_SIZE)
  const input = marshaller.allocBytes(ciphertext)
  if (mod._mpt_make_ec_pair(input, c1, c2) !== SECP_OK) {
    throw new Error(`mpt-crypto: ${label} is not a valid ciphertext`)
  }
  return [c1, c2]
}

/**
 * Copy parsed structs into one contiguous array, as the C `*_vec` parameters
 * expect.
 *
 * @param mod - The loaded WASM module.
 * @param marshaller - The call's marshaller.
 * @param structs - Pointers to parsed structs.
 * @returns A pointer to the contiguous array.
 */
function structArray(
  mod: WasmModule,
  marshaller: Marshaller,
  structs: number[],
): number {
  const out = marshaller.alloc(PUBKEY_STRUCT_SIZE * structs.length)
  structs.forEach((ptr, index) => {
    mod.HEAPU8.copyWithin(
      out + index * PUBKEY_STRUCT_SIZE,
      ptr,
      ptr + PUBKEY_STRUCT_SIZE,
    )
  })
  return out
}

/**
 * Parse the recipients of a Send sigma statement: their shared C1, and the
 * contiguous C2 and public-key arrays.
 *
 * @param mod - The loaded WASM module.
 * @param marshaller - The call's marshaller.
 * @param recipients - The recipients.
 * @returns Pointers to C1, the C2 array and the key array.
 * @throws If the recipients are empty, malformed, or do not share C1.
 */
function parseRecipients(
  mod: WasmModule,
  marshaller: Marshaller,
  recipients: Participant[],
): { c1: number; c2Vec: number; pkVec: number } {
  if (recipients.length === 0) {
    throw new Error('mpt-crypto: recipients must not be empty')
  }
  const raw = recipients.map((recipient, index) =>
    rawParticipant(recipient, `recipients[${index}]`),
  )
  const sharedC1 = bytesToHex(raw[0].ciphertext.slice(0, PUBKEY_SIZE))
  const pairs = raw.map((recipient, index) => {
    if (bytesToHex(recipient.ciphertext.slice(0, PUBKEY_SIZE)) !== sharedC1) {
      throw new Error(
        'mpt-crypto: recipient ciphertexts must share one randomness',
      )
    }
    return parseCiphertext(
      mod,
      marshaller,
      recipient.ciphertext,
      `recipients[${index}].ciphertext`,
    )
  })
  const keys = raw.map((recipient, index) =>
    parsePoint(
      mod,
      marshaller,
      recipient.publicKey,
      `recipients[${index}].publicKey`,
    ),
  )
  return {
    c1: pairs[0][0],
    c2Vec: structArray(
      mod,
      marshaller,
      pairs.map(([, c2]) => c2),
    ),
    pkVec: structArray(mod, marshaller, keys),
  }
}

/**
 * Generate the 192-byte XLS-96 Send sigma proof over any number of recipients.
 *
 * @param params - The statement and witness.
 * @returns The 192-byte hex proof.
 * @throws If inputs are malformed or the WASM call fails.
 */
export async function getSendSigmaProof(
  params: SendSigmaProofParams,
): Promise<string> {
  assertUint64(params.amount, 'amount')
  const priv = hexToBytes(params.privateKey, 'privateKey', PRIVKEY_SIZE)
  const pub = hexToBytes(params.publicKey, 'publicKey', PUBKEY_SIZE)
  const blinding = hexToBytes(
    params.blindingFactor,
    'blindingFactor',
    BLINDING_FACTOR_SIZE,
  )
  const amountCommitment = hexToBytes(
    params.amountCommitment,
    'amountCommitment',
    PEDERSEN_COMMIT_SIZE,
  )
  const balance = rawPedersenParams(params.balanceParams, 'balanceParams')
  const ctx = hexToBytes(params.contextHash, 'contextHash', CONTEXT_HASH_SIZE)
  return withModule((mod, marshaller) => {
    const { c1, c2Vec, pkVec } = parseRecipients(
      mod,
      marshaller,
      params.recipients,
    )
    const pcM = parsePoint(
      mod,
      marshaller,
      amountCommitment,
      'amountCommitment',
    )
    const pkA = parsePoint(mod, marshaller, pub, 'publicKey')
    const pcB = parsePoint(
      mod,
      marshaller,
      balance.commitment,
      'balanceParams.commitment',
    )
    const [b1, b2] = parseCiphertext(
      mod,
      marshaller,
      balance.ciphertext,
      'balanceParams.ciphertext',
    )
    const privPtr = marshaller.allocBytes(priv)
    const blindingPtr = marshaller.allocBytes(blinding)
    const rhoPtr = marshaller.allocBytes(balance.blindingFactor)
    // Wipe the transient JS copies; WASM scratch is zeroed on dispose().
    priv.fill(0)
    blinding.fill(0)
    balance.blindingFactor.fill(0)
    const ctxPtr = marshaller.allocBytes(ctx)
    const outPtr = marshaller.alloc(SEND_SIGMA_PROOF_SIZE)
    if (
      mod._secp256k1_compact_standard_prove(
        mod._mpt_secp256k1_context(),
        outPtr,
        params.amount,
        balance.amount,
        blindingPtr,
        privPtr,
        rhoPtr,
        params.recipients.length,
        c1,
        c2Vec,
        pkVec,
        pcM,
        pkA,
        pcB,
        b1,
        b2,
        ctxPtr,
      ) !== SECP_OK
    ) {
      throw new Error('secp256k1_compact_standard_prove failed')
    }
    return bytesToHex(marshaller.readBytes(outPtr, SEND_SIGMA_PROOF_SIZE))
  })
}

/**
 * Verify a 192-byte XLS-96 Send sigma proof, as rippled does.
 *
 * @param proof - The 192-byte hex proof.
 * @param statement - The public statement.
 * @returns Whether the proof is valid.
 * @throws If inputs are malformed.
 */
export async function verifySendSigmaProof(
  proof: string,
  statement: SendSigmaStatement,
): Promise<boolean> {
  const proofBytes = hexToBytes(proof, 'proof', SEND_SIGMA_PROOF_SIZE)
  const pub = hexToBytes(statement.publicKey, 'publicKey', PUBKEY_SIZE)
  const amountCommitment = hexToBytes(
    statement.amountCommitment,
    'amountCommitment',
    PEDERSEN_COMMIT_SIZE,
  )
  const balanceCommitment = hexToBytes(
    statement.balanceCommitment,
    'balanceCommitment',
    PEDERSEN_COMMIT_SIZE,
  )
  const balanceCiphertext = hexToBytes(
    statement.balanceCiphertext,
    'balanceCiphertext',
    ELGAMAL_TOTAL_SIZE,
  )
  const ctx = hexToBytes(
    statement.contextHash,
    'contextHash',
    CONTEXT_HASH_SIZE,
  )
  return withModule((mod, marshaller) => {
    const { c1, c2Vec, pkVec } = parseRecipients(
      mod,
      marshaller,
      statement.recipients,
    )
    const [b1, b2] = parseCiphertext(
      mod,
      marshaller,
      balanceCiphertext,
      'balanceCiphertext',
    )
    return (
      mod._secp256k1_compact_standard_verify(
        mod._mpt_secp256k1_context(),
        marshaller.allocBytes(proofBytes),
        statement.recipients.length,
        c1,
        c2Vec,
        pkVec,
        parsePoint(mod, marshaller, amountCommitment, 'amountCommitment'),
        parsePoint(mod, marshaller, pub, 'publicKey'),
        parsePoint(mod, marshaller, balanceCommitment, 'balanceCommitment'),
        b1,
        b2,
        marshaller.allocBytes(ctx),
      ) === SECP_OK
    )
  })
}

/**
 * Generate the 128-byte XLS-96 ConvertBack sigma proof: the holder can decrypt
 * a ciphertext, and a commitment commits to its value.
 *
 * @param params - The statement and witness.
 * @returns The 128-byte hex proof.
 * @throws If inputs are malformed or the WASM call fails.
 */
export async function getConvertBackSigmaProof(
  params: ConvertBackSigmaProofParams,
): Promise<string> {
  const priv = hexToBytes(params.privateKey, 'privateKey', PRIVKEY_SIZE)
  const pub = hexToBytes(params.publicKey, 'publicKey', PUBKEY_SIZE)
  const balance = rawPedersenParams(params.balanceParams, 'balanceParams')
  const ctx = hexToBytes(params.contextHash, 'contextHash', CONTEXT_HASH_SIZE)
  return withModule((mod, marshaller) => {
    const pkA = parsePoint(mod, marshaller, pub, 'publicKey')
    const [b1, b2] = parseCiphertext(
      mod,
      marshaller,
      balance.ciphertext,
      'balanceParams.ciphertext',
    )
    const pcB = parsePoint(
      mod,
      marshaller,
      balance.commitment,
      'balanceParams.commitment',
    )
    const privPtr = marshaller.allocBytes(priv)
    const rhoPtr = marshaller.allocBytes(balance.blindingFactor)
    // Wipe the transient JS copies; WASM scratch is zeroed on dispose().
    priv.fill(0)
    balance.blindingFactor.fill(0)
    const outPtr = marshaller.alloc(CONVERT_BACK_SIGMA_PROOF_SIZE)
    if (
      mod._secp256k1_compact_convertback_prove(
        mod._mpt_secp256k1_context(),
        outPtr,
        balance.amount,
        privPtr,
        rhoPtr,
        pkA,
        b1,
        b2,
        pcB,
        marshaller.allocBytes(ctx),
      ) !== SECP_OK
    ) {
      throw new Error('secp256k1_compact_convertback_prove failed')
    }
    return bytesToHex(
      marshaller.readBytes(outPtr, CONVERT_BACK_SIGMA_PROOF_SIZE),
    )
  })
}

/**
 * Verify a 128-byte XLS-96 ConvertBack sigma proof, as rippled does.
 *
 * @param proof - The 128-byte hex proof.
 * @param statement - The public statement.
 * @returns Whether the proof is valid.
 * @throws If inputs are malformed.
 */
export async function verifyConvertBackSigmaProof(
  proof: string,
  statement: ConvertBackSigmaStatement,
): Promise<boolean> {
  const proofBytes = hexToBytes(proof, 'proof', CONVERT_BACK_SIGMA_PROOF_SIZE)
  const pub = hexToBytes(statement.publicKey, 'publicKey', PUBKEY_SIZE)
  const ciphertext = hexToBytes(
    statement.ciphertext,
    'ciphertext',
    ELGAMAL_TOTAL_SIZE,
  )
  const commitment = hexToBytes(
    statement.commitment,
    'commitment',
    PEDERSEN_COMMIT_SIZE,
  )
  const ctx = hexToBytes(
    statement.contextHash,
    'contextHash',
    CONTEXT_HASH_SIZE,
  )
  return withModule((mod, marshaller) => {
    const [b1, b2] = parseCiphertext(mod, marshaller, ciphertext, 'ciphertext')
    return (
      mod._secp256k1_compact_convertback_verify(
        mod._mpt_secp256k1_context(),
        marshaller.allocBytes(proofBytes),
        parsePoint(mod, marshaller, pub, 'publicKey'),
        b1,
        b2,
        parsePoint(mod, marshaller, commitment, 'commitment'),
        marshaller.allocBytes(ctx),
      ) === SECP_OK
    )
  })
}

/**
 * Generate an aggregated Bulletproof that each value is in [0, 2^64), over the
 * commitments `value*G + blindingFactor*H`.
 *
 * @param values - One or two values.
 * @param blindingFactors - The matching 32-byte hex blinding factors.
 * @param contextHash - The 32-byte transaction context hash.
 * @returns The 688-byte (one value) or 754-byte (two values) hex proof.
 * @throws If inputs are malformed or the WASM call fails.
 */
export async function getAggregatedRangeProof(
  values: bigint[],
  blindingFactors: string[],
  contextHash: string,
): Promise<string> {
  if (
    values.length === 0 ||
    values.length > MAX_RANGE_VALUES ||
    values.length !== blindingFactors.length
  ) {
    throw new Error(
      'getAggregatedRangeProof: pass one or two values with one blinding factor each',
    )
  }
  values.forEach((value, index) => assertUint64(value, `values[${index}]`))
  const blindings = blindingFactors.map((blinding, index) =>
    hexToBytes(blinding, `blindingFactors[${index}]`, BLINDING_FACTOR_SIZE),
  )
  const ctx = hexToBytes(contextHash, 'contextHash', CONTEXT_HASH_SIZE)
  const size =
    values.length === 1 ? SINGLE_BULLETPROOF_SIZE : DOUBLE_BULLETPROOF_SIZE
  return withModule((mod, marshaller) => {
    const ctxSecp = mod._mpt_secp256k1_context()
    const valuesPtr = marshaller.alloc(U64_BYTES * values.length)
    values.forEach((value, index) => {
      marshaller.writeU64(valuesPtr + index * U64_BYTES, value)
    })
    const blindingsPtr = marshaller.alloc(BLINDING_FACTOR_SIZE * values.length)
    blindings.forEach((blinding, index) => {
      mod.HEAPU8.set(blinding, blindingsPtr + index * BLINDING_FACTOR_SIZE)
      // Wipe the transient JS copy; WASM scratch is zeroed on dispose().
      blinding.fill(0)
    })
    const hPtr = marshaller.alloc(PUBKEY_STRUCT_SIZE)
    if (mod._secp256k1_mpt_get_h_generator(ctxSecp, hPtr) !== SECP_OK) {
      throw new Error('secp256k1_mpt_get_h_generator failed')
    }
    const outPtr = marshaller.alloc(size)
    const outLenPtr = marshaller.alloc(SIZE_T_BYTES)
    marshaller.writeU32(outLenPtr, size)
    if (
      mod._secp256k1_bulletproof_prove_agg(
        ctxSecp,
        outPtr,
        outLenPtr,
        valuesPtr,
        blindingsPtr,
        values.length,
        hPtr,
        marshaller.allocBytes(ctx),
      ) !== SECP_OK ||
      marshaller.readU32(outLenPtr) !== size
    ) {
      throw new Error('secp256k1_bulletproof_prove_agg failed')
    }
    return bytesToHex(marshaller.readBytes(outPtr, size))
  })
}

/**
 * Verify an aggregated Bulletproof, as rippled does.
 *
 * @param proof - The 688- or 754-byte hex proof.
 * @param commitments - The one or two 33-byte hex commitments it covers.
 * @param contextHash - The 32-byte transaction context hash.
 * @returns Whether the proof is valid.
 * @throws If inputs are malformed.
 */
export async function verifyAggregatedRangeProof(
  proof: string,
  commitments: string[],
  contextHash: string,
): Promise<boolean> {
  const proofBytes = hexToBytes(proof, 'proof')
  const points = commitments.map((commitment, index) =>
    hexToBytes(commitment, `commitments[${index}]`, PEDERSEN_COMMIT_SIZE),
  )
  const ctx = hexToBytes(contextHash, 'contextHash', CONTEXT_HASH_SIZE)
  return withModule((mod, marshaller) => {
    // An array of pointers to the compressed commitments.
    const pointers = marshaller.alloc(POINTER_BYTES * points.length)
    points.forEach((point, index) => {
      marshaller.writeU32(
        pointers + index * POINTER_BYTES,
        marshaller.allocBytes(point),
      )
    })
    return (
      mod._mpt_verify_aggregated_bulletproof(
        marshaller.allocBytes(proofBytes),
        proofBytes.length,
        pointers,
        points.length,
        marshaller.allocBytes(ctx),
      ) === 0
    )
  })
}

/**
 * Verify a 64-byte XLS-96 Clawback sigma proof that `ciphertext`, under
 * `publicKey`, encrypts `amount`, as rippled does. With amount 0 over a
 * ciphertext difference it proves two ciphertexts encrypt the same value.
 *
 * @param proof - The 64-byte hex proof.
 * @param amount - The amount the ciphertext encrypts.
 * @param publicKey - The 33-byte hex public key.
 * @param ciphertext - The 66-byte hex ciphertext.
 * @param contextHash - The 32-byte transaction context hash.
 * @returns Whether the proof is valid.
 * @throws If inputs are malformed.
 */
// eslint-disable-next-line max-params -- mirrors the C ABI
export async function verifyClawbackProof(
  proof: string,
  amount: bigint,
  publicKey: string,
  ciphertext: string,
  contextHash: string,
): Promise<boolean> {
  assertUint64(amount, 'amount')
  const proofBytes = hexToBytes(proof, 'proof', CLAWBACK_PROOF_SIZE)
  const pub = hexToBytes(publicKey, 'publicKey', PUBKEY_SIZE)
  const ct = hexToBytes(ciphertext, 'ciphertext', ELGAMAL_TOTAL_SIZE)
  const ctx = hexToBytes(contextHash, 'contextHash', CONTEXT_HASH_SIZE)
  return withModule(
    (mod, marshaller) =>
      mod._mpt_verify_clawback_proof(
        marshaller.allocBytes(proofBytes),
        amount,
        marshaller.allocBytes(pub),
        marshaller.allocBytes(ct),
        marshaller.allocBytes(ctx),
      ) === 0,
  )
}

/**
 * Decode a 32-byte big-endian hex scalar.
 *
 * @param scalar - The hex scalar.
 * @param label - A human-readable name used in error messages.
 * @returns The scalar.
 */
function toScalar(scalar: string, label: string): bigint {
  hexToBytes(scalar, label, BLINDING_FACTOR_SIZE)
  return BigInt(`0x${scalar}`) % CURVE_ORDER
}

/**
 * Encode a scalar mod n as 32-byte big-endian hex.
 *
 * @param value - The scalar.
 * @returns The uppercase hex scalar.
 */
function fromScalar(value: bigint): string {
  const reduced = ((value % CURVE_ORDER) + CURVE_ORDER) % CURVE_ORDER
  return reduced
    .toString(16)
    .toUpperCase()
    .padStart(BLINDING_FACTOR_SIZE * 2, '0')
}

/**
 * Subtract two blinding factors mod the curve order: the blinding factor of the
 * difference of two Pedersen commitments.
 *
 * @param a - A 32-byte hex scalar.
 * @param b - A 32-byte hex scalar.
 * @returns `a - b mod n` as 32-byte hex.
 */
export function subtractScalars(a: string, b: string): string {
  return fromScalar(toScalar(a, 'a') - toScalar(b, 'b'))
}

/**
 * Multiply a blinding factor by an integer mod the curve order: the blinding
 * factor of an integer multiple of a Pedersen commitment.
 *
 * @param a - A 32-byte hex scalar.
 * @param multiplier - The integer multiplier.
 * @returns `a * multiplier mod n` as 32-byte hex.
 */
export function multiplyScalar(a: string, multiplier: bigint): string {
  return fromScalar(toScalar(a, 'a') * multiplier)
}
