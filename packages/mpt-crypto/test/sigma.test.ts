import {
  addCiphertexts,
  encryptAmount,
  generateBlindingFactor,
  getAggregatedRangeProof,
  getConfidentialSendProof,
  getConvertBackProof,
  getConvertBackSigmaProof,
  getPedersenCommitment,
  getSendSigmaProof,
  multiplyScalar,
  subtractCiphertexts,
  subtractScalars,
  getClawbackProof,
  verifyAggregatedRangeProof,
  verifyClawbackProof,
  verifyConvertBackSigmaProof,
  verifySendSigmaProof,
} from '../src'

const PUBLIC_KEY =
  '0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020'
const PRIVATE_KEY =
  '1ACAAEDECE405B2A958212629E16F2EB46B153EEE94CDD350FDEFF52795525B7'
const DEST_KEY =
  '039DA5E1E7CB517D0039C2E1DA01F81978EF6675694C65A285D67B79F09588B143'
const ISSUER_KEY =
  '038EA8465AC65D2F2EE9D68CA619586E51A740F5BA8A80A3769BBDCA2F97427581'
const CONTEXT_HASH = 'A1'.repeat(32)
const OTHER_CONTEXT_HASH = 'B2'.repeat(32)

/**
 * A holder's balance of `balance` under PUBLIC_KEY, with a fresh commitment.
 *
 * @param balance - The balance.
 * @returns The balance witness.
 */
async function balanceWitness(balance: bigint): Promise<{
  commitment: string
  amount: bigint
  ciphertext: string
  blindingFactor: string
}> {
  const rho = await generateBlindingFactor()
  return {
    commitment: await getPedersenCommitment(balance, rho),
    amount: balance,
    ciphertext: await encryptAmount(
      balance,
      PUBLIC_KEY,
      await generateBlindingFactor(),
    ),
    blindingFactor: rho,
  }
}

/**
 * The first 33 bytes of a homomorphic combination of commitments, each encoded
 * as the pair `PC || PC` so the ciphertext ops apply to it.
 *
 * @param a - A 33-byte hex commitment.
 * @param b - A 33-byte hex commitment.
 * @param op - The combination.
 * @returns The combined commitment.
 */
async function combine(
  a: string,
  b: string,
  op: typeof addCiphertexts,
): Promise<string> {
  return (await op(a + a, b + b)).slice(0, 66)
}

describe('sigma', () => {
  it('getSendSigmaProof proves the relation the Send proof does', async () => {
    const amount = 300n
    const blinding = await generateBlindingFactor()
    const recipients = await Promise.all(
      [PUBLIC_KEY, DEST_KEY, ISSUER_KEY].map(async (publicKey) => ({
        publicKey,
        ciphertext: await encryptAmount(amount, publicKey, blinding),
      })),
    )
    const amountCommitment = await getPedersenCommitment(amount, blinding)
    const balanceParams = await balanceWitness(1000n)

    const sigma = await getSendSigmaProof({
      privateKey: PRIVATE_KEY,
      publicKey: PUBLIC_KEY,
      amount,
      blindingFactor: blinding,
      recipients,
      amountCommitment,
      balanceParams,
      contextHash: CONTEXT_HASH,
    })
    const send = await getConfidentialSendProof({
      privateKey: PRIVATE_KEY,
      publicKey: PUBLIC_KEY,
      amount,
      participants: recipients,
      txBlindingFactor: blinding,
      contextHash: CONTEXT_HASH,
      amountCommitment,
      balanceParams,
    })
    expect(sigma).toHaveLength(384)

    const statement = {
      publicKey: PUBLIC_KEY,
      recipients,
      amountCommitment,
      balanceCommitment: balanceParams.commitment,
      balanceCiphertext: balanceParams.ciphertext,
      contextHash: CONTEXT_HASH,
    }
    // The nonces are hedged with fresh entropy, so proofs differ byte-for-byte;
    // instead the verifier must accept both the standalone proof and the Send
    // proof's leading sigma part, tying the statement marshalling to mpt-crypto's.
    expect(await verifySendSigmaProof(sigma, statement)).toBe(true)
    expect(await verifySendSigmaProof(send.slice(0, 384), statement)).toBe(true)
    expect(
      await verifySendSigmaProof(sigma, {
        ...statement,
        contextHash: OTHER_CONTEXT_HASH,
      }),
    ).toBe(false)
  })

  it('getSendSigmaProof proves a single recipient', async () => {
    const amount = 42n
    const blinding = await generateBlindingFactor()
    const recipients = [
      {
        publicKey: DEST_KEY,
        ciphertext: await encryptAmount(amount, DEST_KEY, blinding),
      },
    ]
    const amountCommitment = await getPedersenCommitment(amount, blinding)
    const balanceParams = await balanceWitness(500n)
    const sigma = await getSendSigmaProof({
      privateKey: PRIVATE_KEY,
      publicKey: PUBLIC_KEY,
      amount,
      blindingFactor: blinding,
      recipients,
      amountCommitment,
      balanceParams,
      contextHash: CONTEXT_HASH,
    })
    expect(
      await verifySendSigmaProof(sigma, {
        publicKey: PUBLIC_KEY,
        recipients,
        amountCommitment,
        balanceCommitment: balanceParams.commitment,
        balanceCiphertext: balanceParams.ciphertext,
        contextHash: CONTEXT_HASH,
      }),
    ).toBe(true)
  })

  it('rejects recipients that do not share one randomness', async () => {
    const blinding = await generateBlindingFactor()
    await expect(
      getSendSigmaProof({
        privateKey: PRIVATE_KEY,
        publicKey: PUBLIC_KEY,
        amount: 1n,
        blindingFactor: blinding,
        recipients: [
          {
            publicKey: DEST_KEY,
            ciphertext: await encryptAmount(1n, DEST_KEY, blinding),
          },
          {
            publicKey: ISSUER_KEY,
            ciphertext: await encryptAmount(
              1n,
              ISSUER_KEY,
              await generateBlindingFactor(),
            ),
          },
        ],
        amountCommitment: await getPedersenCommitment(1n, blinding),
        balanceParams: await balanceWitness(10n),
        contextHash: CONTEXT_HASH,
      }),
    ).rejects.toThrow(/share one randomness/u)
  })

  it('getConvertBackSigmaProof proves the relation the ConvertBack proof does', async () => {
    const balanceParams = await balanceWitness(1000n)
    const sigma = await getConvertBackSigmaProof({
      privateKey: PRIVATE_KEY,
      publicKey: PUBLIC_KEY,
      balanceParams,
      contextHash: CONTEXT_HASH,
    })
    const convertBack = await getConvertBackProof(
      PRIVATE_KEY,
      PUBLIC_KEY,
      CONTEXT_HASH,
      100n,
      balanceParams,
    )
    expect(sigma).toHaveLength(256)

    const statement = {
      publicKey: PUBLIC_KEY,
      ciphertext: balanceParams.ciphertext,
      commitment: balanceParams.commitment,
      contextHash: CONTEXT_HASH,
    }
    expect(await verifyConvertBackSigmaProof(sigma, statement)).toBe(true)
    expect(
      await verifyConvertBackSigmaProof(convertBack.slice(0, 256), statement),
    ).toBe(true)
    expect(
      await verifyConvertBackSigmaProof(sigma, {
        ...statement,
        commitment: await getPedersenCommitment(
          999n,
          balanceParams.blindingFactor,
        ),
      }),
    ).toBe(false)
  })

  it('getAggregatedRangeProof proves one or two values in range', async () => {
    const [r1, r2] = await Promise.all([
      generateBlindingFactor(),
      generateBlindingFactor(),
    ])
    const [pc1, pc2] = await Promise.all([
      getPedersenCommitment(7n, r1),
      getPedersenCommitment(2n ** 64n - 1n, r2),
    ])

    const double = await getAggregatedRangeProof(
      [7n, 2n ** 64n - 1n],
      [r1, r2],
      CONTEXT_HASH,
    )
    expect(double).toHaveLength(754 * 2)
    expect(
      await verifyAggregatedRangeProof(double, [pc1, pc2], CONTEXT_HASH),
    ).toBe(true)
    expect(
      await verifyAggregatedRangeProof(double, [pc2, pc1], CONTEXT_HASH),
    ).toBe(false)
    expect(
      await verifyAggregatedRangeProof(double, [pc1, pc2], OTHER_CONTEXT_HASH),
    ).toBe(false)

    const single = await getAggregatedRangeProof([7n], [r1], CONTEXT_HASH)
    expect(single).toHaveLength(688 * 2)
    expect(await verifyAggregatedRangeProof(single, [pc1], CONTEXT_HASH)).toBe(
      true,
    )
  })

  it('rejects a range proof over the wrong number of values', async () => {
    await expect(getAggregatedRangeProof([], [], CONTEXT_HASH)).rejects.toThrow(
      /one or two values/u,
    )
    await expect(
      getAggregatedRangeProof([1n], [], CONTEXT_HASH),
    ).rejects.toThrow(/one or two values/u)
  })

  it('subtractScalars and multiplyScalar track commitment arithmetic', async () => {
    const [ra, rb] = await Promise.all([
      generateBlindingFactor(),
      generateBlindingFactor(),
    ])
    const [pcA, pcB] = await Promise.all([
      getPedersenCommitment(50n, ra),
      getPedersenCommitment(20n, rb),
    ])
    // PC(50, ra) - PC(20, rb) = PC(30, ra - rb)
    expect(await combine(pcA, pcB, subtractCiphertexts)).toBe(
      await getPedersenCommitment(30n, subtractScalars(ra, rb)),
    )
    // 3 * PC(20, rb) = PC(60, 3 * rb)
    const doubled = await combine(pcB, pcB, addCiphertexts)
    expect(await combine(doubled, pcB, addCiphertexts)).toBe(
      await getPedersenCommitment(60n, multiplyScalar(rb, 3n)),
    )
  })

  it('verifyClawbackProof checks a ciphertext encrypts an amount', async () => {
    const ciphertext = await encryptAmount(
      77n,
      PUBLIC_KEY,
      await generateBlindingFactor(),
    )
    const proof = await getClawbackProof(
      PRIVATE_KEY,
      PUBLIC_KEY,
      CONTEXT_HASH,
      77n,
      ciphertext,
    )
    expect(
      await verifyClawbackProof(
        proof,
        77n,
        PUBLIC_KEY,
        ciphertext,
        CONTEXT_HASH,
      ),
    ).toBe(true)
    expect(
      await verifyClawbackProof(
        proof,
        78n,
        PUBLIC_KEY,
        ciphertext,
        CONTEXT_HASH,
      ),
    ).toBe(false)
  })
})
