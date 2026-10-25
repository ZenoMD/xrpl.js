import {
  addCiphertexts,
  decryptAmount,
  encryptAmount,
  generateBlindingFactor,
  subtractCiphertexts,
  verifyAggregatedRangeProof,
  verifyClawbackProof,
  verifyConvertBackSigmaProof,
  verifySendSigmaProof,
} from '@xrplf/mpt-crypto'
import { assert } from 'chai'
import { decode, encode } from 'ripple-binary-codec'

import { type Client, validate } from '../../src'
import {
  deriveConfidentialKeypair,
  getConfidentialLoanPayContextHash,
  getLoanSetContextHash,
  prepareConfidentialLoanPay,
  prepareConfidentialLoanSet,
} from '../../src/confidential'
import { XrplError } from '../../src/errors'
import { LoanBrokerFlags, LoanFlags } from '../../src/models/ledger'
import { ConfidentialLoanPayFlags } from '../../src/models/transactions'

const BROKER = deriveConfidentialKeypair()
const BORROWER = deriveConfidentialKeypair()
const ISSUER = deriveConfidentialKeypair()
const AUDITOR = deriveConfidentialKeypair()
const LOAN_AUDITOR = deriveConfidentialKeypair()

const OWNER = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh'
const PSEUDO_ACCOUNT = 'rLpgximdBvEHy8TxUwyj6mjCRNcJju5qGG'
const BORROWER_ADDRESS = 'rPGxCzMicNJRe1U1CD5QyNjXdLUtdgSa7B'
const ISSUANCE_ID = 'AB'.repeat(24)
const VAULT_ID = 'AA'.repeat(32)
const LOAN_BROKER_ID = 'BB'.repeat(32)
const LOAN_ID = 'CC'.repeat(32)

const LENDING_BALANCE = 1000n
const LENDING_VERSION = 3
const BORROWER_BALANCE = 2000n
const BORROWER_VERSION = 5
const LOAN_VERSION = 2
const SEQUENCE = 7

// Proof part sizes, in hex characters.
const SEND = 946 * 2
const SIGMA = 192 * 2
const RANGE = 754 * 2
const LINK = 128 * 2

interface Ledger {
  lendingSpending: string
  borrowerSpending: string
  loan?: Record<string, unknown>
}

/**
 * Encrypt a fixed balance under a key.
 *
 * @param amount - The balance.
 * @param publicKey - The holder's key.
 * @returns The ciphertext.
 */
async function encryptBalance(
  amount: bigint,
  publicKey: string,
): Promise<string> {
  return encryptAmount(amount, publicKey, await generateBlindingFactor())
}

/**
 * A Client stub serving a confidential LoanBroker, its Lending Balance, a
 * Borrower with a confidential balance, and optionally a confidential Loan.
 *
 * @param ledger - The confidential balances and Loan to serve.
 * @returns The stub Client.
 */
function loanClient(ledger: Ledger): Client {
  const nodes: Record<string, unknown> = {
    [VAULT_ID]: { Asset: { mpt_issuance_id: ISSUANCE_ID } },
    [LOAN_BROKER_ID]: {
      index: LOAN_BROKER_ID,
      Flags: LoanBrokerFlags.lsfLoanBrokerConfidential,
      VaultID: VAULT_ID,
      Account: PSEUDO_ACCOUNT,
      Owner: OWNER,
    },
    [LOAN_ID]: ledger.loan,
  }
  const tokens: Record<string, unknown> = {
    [PSEUDO_ACCOUNT]: {
      HolderEncryptionKey: BROKER.publicKey,
      ConfidentialBalanceSpending: ledger.lendingSpending,
      ConfidentialBalanceVersion: LENDING_VERSION,
    },
    [BORROWER_ADDRESS]: {
      HolderEncryptionKey: BORROWER.publicKey,
      ConfidentialBalanceSpending: ledger.borrowerSpending,
      ConfidentialBalanceVersion: BORROWER_VERSION,
    },
  }
  const request = async (req: {
    command: string
    index?: string
    mpt_issuance?: string
    mptoken?: { account: string }
  }): Promise<unknown> => {
    if (req.command === 'account_info') {
      return { result: { account_data: { Sequence: SEQUENCE } } }
    }
    if (req.index != null) {
      return { result: { node: nodes[req.index] } }
    }
    if (req.mpt_issuance != null) {
      return {
        result: {
          node: {
            IssuerEncryptionKey: ISSUER.publicKey,
            AuditorEncryptionKey: AUDITOR.publicKey,
            ConfidentialOutstandingAmount: '10000',
          },
        },
      }
    }
    if (req.mptoken != null) {
      return { result: { node: tokens[req.mptoken.account] } }
    }
    throw new Error(`unexpected request: ${JSON.stringify(req)}`)
  }
  return { request, getLedgerIndex: async () => 100 } as unknown as Client
}

/**
 * A sum of integer multiples of commitments, via the ciphertext ops on the pair
 * `PC || PC`. The first multiplier must be positive.
 *
 * @param terms - Each commitment and its non-zero integer multiplier.
 * @returns The combined commitment.
 */
async function combine(terms: Array<[string, number]>): Promise<string> {
  const pairs = terms.flatMap(([point, multiplier]) =>
    Array.from({ length: Math.abs(multiplier) }, () => ({
      pair: point + point,
      add: multiplier > 0,
    })),
  )
  const [first, ...rest] = pairs
  let sum = first.pair
  for (const { pair, add } of rest) {
    // eslint-disable-next-line no-await-in-loop -- a sequential homomorphic sum
    sum = await (add
      ? addCiphertexts(sum, pair)
      : subtractCiphertexts(sum, pair))
  }
  return sum.slice(0, 66)
}

/**
 * Split a proof into parts of the given hex lengths.
 *
 * @param proof - The concatenated proof.
 * @param sizes - Each part's length in hex characters.
 * @returns The parts.
 */
function split(proof: string, sizes: number[]): string[] {
  let offset = 0
  return sizes.map((size) => {
    const part = proof.slice(offset, offset + size)
    offset += size
    return part
  })
}

/**
 * Assert that a transaction passes model validation and survives a binary codec
 * round trip unchanged.
 *
 * @param tx - The transaction to check.
 */
function assertEncodable(tx: object): void {
  validate(tx as Record<string, unknown>)
  assert.deepEqual(decode(encode(tx as Record<string, unknown>)), tx)
}

/**
 * Assert that a builder call rejects with an {@link XrplError} matching `pattern`.
 *
 * @param promise - The pending builder call.
 * @param pattern - The expected message pattern.
 */
async function expectXrplError(
  promise: Promise<unknown>,
  pattern: RegExp,
): Promise<void> {
  let error: unknown
  try {
    await promise
  } catch (err) {
    error = err
  }
  assert.instanceOf(error, XrplError)
  assert.match((error as Error).message, pattern)
}

/**
 * Verify an XLS-96 Send proof's two halves: the sigma proof over its four
 * participants and the range proof over the amount and the remaining balance.
 *
 * @param proof - The 946-byte hex Send proof.
 * @param statement - The Send statement.
 * @param statement.publicKey - The sender's key.
 * @param statement.recipients - Sender, destination, issuer, MPT Auditor.
 * @param statement.amountCommitment - `AmountCommitment`.
 * @param statement.balanceCommitment - `BalanceCommitment`.
 * @param statement.balanceCiphertext - The sender's spending balance.
 * @param statement.contextHash - The context hash.
 */
async function assertSendProof(
  proof: string,
  statement: {
    publicKey: string
    recipients: Array<{ publicKey: string; ciphertext: string }>
    amountCommitment: string
    balanceCommitment: string
    balanceCiphertext: string
    contextHash: string
  },
): Promise<void> {
  assert.isTrue(await verifySendSigmaProof(proof.slice(0, SIGMA), statement))
  assert.isTrue(
    await verifyAggregatedRangeProof(
      proof.slice(SIGMA),
      [
        statement.amountCommitment,
        await combine([
          [statement.balanceCommitment, 1],
          [statement.amountCommitment, -1],
        ]),
      ],
      statement.contextHash,
    ),
  )
}

// Real proofs: building and verifying them takes a few seconds.
jest.setTimeout(60_000)

describe('confidential/loan', function () {
  const terms = {
    principal: 600n,
    amountOwed: 660n,
    periodicPayment: 60n,
    paymentTotal: 12,
  }

  describe('prepareConfidentialLoanSet', function () {
    it('builds a LoanSet whose every proof part verifies as rippled checks it', async function () {
      const lendingSpending = await encryptBalance(
        LENDING_BALANCE,
        BROKER.publicKey,
      )
      const client = loanClient({
        lendingSpending,
        borrowerSpending: await encryptBalance(
          BORROWER_BALANCE,
          BORROWER.publicKey,
        ),
      })
      const tx = await prepareConfidentialLoanSet(client, {
        account: OWNER,
        loanBrokerID: LOAN_BROKER_ID,
        borrower: BORROWER_ADDRESS,
        brokerKeypair: BROKER,
        loanAuditorKey: LOAN_AUDITOR.publicKey,
        paymentInterval: 600,
        ...terms,
      })

      assert.strictEqual(tx.Account, OWNER)
      assert.strictEqual(tx.Counterparty, BORROWER_ADDRESS)
      assert.strictEqual(tx.Sequence, SEQUENCE)
      assert.strictEqual(tx.PaymentTotal, 12)
      assert.isUndefined(tx.PrincipalRequested)
      assert.lengthOf(tx.ZKProof as string, 3030 * 2)
      assertEncodable(tx)

      const contextHash = getLoanSetContextHash(
        PSEUDO_ACCOUNT,
        ISSUANCE_ID,
        SEQUENCE,
        BORROWER_ADDRESS,
        LENDING_VERSION,
      )
      const [send, auditorPart, owedPart, periodicPart, range, schedule] =
        split(tx.ZKProof as string, [SEND, SIGMA, SIGMA, SIGMA, RANGE, RANGE])
      const balance = {
        publicKey: BROKER.publicKey,
        balanceCommitment: tx.BalanceCommitment as string,
        balanceCiphertext: lendingSpending,
        contextHash,
      }

      // Part 1: the principal transfer, as an XLS-96 Send.
      await assertSendProof(send, {
        ...balance,
        recipients: [
          {
            publicKey: BROKER.publicKey,
            ciphertext: tx.SenderEncryptedAmount!,
          },
          {
            publicKey: BORROWER.publicKey,
            ciphertext: tx.DestinationEncryptedAmount!,
          },
          {
            publicKey: ISSUER.publicKey,
            ciphertext: tx.IssuerEncryptedAmount!,
          },
          {
            publicKey: AUDITOR.publicKey,
            ciphertext: tx.AuditorEncryptedAmount!,
          },
        ],
        amountCommitment: tx.AmountCommitment!,
      })
      // Parts 2-4: the Loan Auditor's principal and the terms' ciphertexts.
      assert.isTrue(
        await verifySendSigmaProof(auditorPart, {
          ...balance,
          recipients: [
            {
              publicKey: LOAN_AUDITOR.publicKey,
              ciphertext: tx.LoanAuditorEncryptedPrincipal!,
            },
          ],
          amountCommitment: tx.AmountCommitment!,
        }),
      )
      assert.isTrue(
        await verifySendSigmaProof(owedPart, {
          ...balance,
          recipients: [
            {
              publicKey: BORROWER.publicKey,
              ciphertext: tx.BorrowerEncryptedAmountOwed!,
            },
            {
              publicKey: BROKER.publicKey,
              ciphertext: tx.BrokerEncryptedAmountOwed!,
            },
            {
              publicKey: LOAN_AUDITOR.publicKey,
              ciphertext: tx.LoanAuditorEncryptedAmountOwed!,
            },
          ],
          amountCommitment: tx.AmountOwedCommitment!,
        }),
      )
      assert.isTrue(
        await verifySendSigmaProof(periodicPart, {
          ...balance,
          recipients: [
            {
              publicKey: BORROWER.publicKey,
              ciphertext: tx.BorrowerEncryptedPeriodicPayment!,
            },
            {
              publicKey: BROKER.publicKey,
              ciphertext: tx.BrokerEncryptedPeriodicPayment!,
            },
            {
              publicKey: LOAN_AUDITOR.publicKey,
              ciphertext: tx.LoanAuditorEncryptedPeriodicPayment!,
            },
          ],
          amountCommitment: tx.PeriodicPaymentCommitment!,
        }),
      )
      // Part 5: O, Q >= 0.
      assert.isTrue(
        await verifyAggregatedRangeProof(
          range,
          [tx.AmountOwedCommitment!, tx.PeriodicPaymentCommitment!],
          contextHash,
        ),
      )
      // Part 6: O >= P and N*Q >= O.
      assert.isTrue(
        await verifyAggregatedRangeProof(
          schedule,
          [
            await combine([
              [tx.AmountOwedCommitment!, 1],
              [tx.AmountCommitment!, -1],
            ]),
            await combine([
              [tx.PeriodicPaymentCommitment!, terms.paymentTotal],
              [tx.AmountOwedCommitment!, -1],
            ]),
          ],
          contextHash,
        ),
      )

      // Each party reads its copy of the terms.
      assert.strictEqual(
        await decryptAmount(
          tx.DestinationEncryptedAmount!,
          BORROWER.privateKey,
          1000n,
        ),
        600n,
      )
      assert.strictEqual(
        await decryptAmount(
          tx.BrokerEncryptedAmountOwed!,
          BROKER.privateKey,
          1000n,
        ),
        660n,
      )
      assert.strictEqual(
        await decryptAmount(
          tx.LoanAuditorEncryptedPeriodicPayment!,
          LOAN_AUDITOR.privateKey,
          1000n,
        ),
        60n,
      )
    })

    it('names the broker owner as Counterparty when the Borrower submits', async function () {
      const client = loanClient({
        lendingSpending: await encryptBalance(
          LENDING_BALANCE,
          BROKER.publicKey,
        ),
        borrowerSpending: await encryptBalance(
          BORROWER_BALANCE,
          BORROWER.publicKey,
        ),
      })
      const tx = await prepareConfidentialLoanSet(client, {
        account: BORROWER_ADDRESS,
        loanBrokerID: LOAN_BROKER_ID,
        borrower: BORROWER_ADDRESS,
        brokerKeypair: BROKER,
        loanAuditorKey: LOAN_AUDITOR.publicKey,
        ...terms,
      })
      assert.strictEqual(tx.Account, BORROWER_ADDRESS)
      assert.strictEqual(tx.Counterparty, OWNER)
    })

    it('rejects inconsistent terms before proving them', async function () {
      const client = loanClient({
        lendingSpending: await encryptBalance(
          LENDING_BALANCE,
          BROKER.publicKey,
        ),
        borrowerSpending: await encryptBalance(
          BORROWER_BALANCE,
          BORROWER.publicKey,
        ),
      })
      const base = {
        account: OWNER,
        loanBrokerID: LOAN_BROKER_ID,
        borrower: BORROWER_ADDRESS,
        brokerKeypair: BROKER,
        loanAuditorKey: LOAN_AUDITOR.publicKey,
        ...terms,
      }
      await expectXrplError(
        prepareConfidentialLoanSet(client, { ...base, amountOwed: 599n }),
        /at least the principal/u,
      )
      await expectXrplError(
        prepareConfidentialLoanSet(client, { ...base, periodicPayment: 54n }),
        /at least amountOwed/u,
      )
      await expectXrplError(
        prepareConfidentialLoanSet(client, {
          ...base,
          principal: 1001n,
          amountOwed: 1100n,
          periodicPayment: 100n,
        }),
        /exceeds the spendable Lending Balance/u,
      )
      await expectXrplError(
        prepareConfidentialLoanSet(client, {
          ...base,
          brokerKeypair: BORROWER,
        }),
        /not the Broker Key/u,
      )
      await expectXrplError(
        prepareConfidentialLoanSet(client, {
          ...base,
          account: PSEUDO_ACCOUNT,
        }),
        /LoanBroker owner or the Borrower/u,
      )
    })
  })

  describe('prepareConfidentialLoanPay', function () {
    /**
     * A Client serving a confidential Loan created with `terms`.
     *
     * @param paymentRemaining - The Loan's `PaymentRemaining`.
     * @returns The stub Client and the Borrower's spending balance.
     */
    async function payClient(
      paymentRemaining = 12,
    ): Promise<{ client: Client; borrowerSpending: string }> {
      const bf = await generateBlindingFactor()
      const enc = async (value: bigint, key: string): Promise<string> =>
        encryptAmount(value, key, bf)
      const borrowerSpending = await encryptBalance(
        BORROWER_BALANCE,
        BORROWER.publicKey,
      )
      const client = loanClient({
        lendingSpending: await encryptBalance(
          LENDING_BALANCE,
          BROKER.publicKey,
        ),
        borrowerSpending,
        loan: {
          Flags: LoanFlags.lsfLoanConfidential,
          LoanBrokerID: LOAN_BROKER_ID,
          Borrower: BORROWER_ADDRESS,
          PaymentRemaining: paymentRemaining,
          ConfidentialLoanVersion: LOAN_VERSION,
          LoanAuditorEncryptionKey: LOAN_AUDITOR.publicKey,
          BorrowerEncryptedAmountOwed: await enc(
            terms.amountOwed,
            BORROWER.publicKey,
          ),
          BorrowerEncryptedPeriodicPayment: await enc(
            terms.periodicPayment,
            BORROWER.publicKey,
          ),
        },
      })
      return { client, borrowerSpending }
    }

    /**
     * The Loan entry `payClient` serves.
     *
     * @param client - The stub Client.
     * @returns The Loan entry.
     */
    async function fetchLoan(client: Client): Promise<Record<string, string>> {
      const response = (await client.request({
        command: 'ledger_entry',
        index: LOAN_ID,
      })) as unknown as { result: { node: Record<string, string> } }
      return response.result.node
    }

    const payContextHash = getConfidentialLoanPayContextHash({
      borrower: BORROWER_ADDRESS,
      mptIssuanceID: ISSUANCE_ID,
      sequence: SEQUENCE,
      brokerPseudoAccount: PSEUDO_ACCOUNT,
      borrowerVersion: BORROWER_VERSION,
      loanID: LOAN_ID,
      loanVersion: LOAN_VERSION,
    })

    /**
     * Verify the parts a regular and a full payment share: the Send proof and
     * the Loan Auditor's sigma proof.
     *
     * @param tx - The ConfidentialLoanPay.
     * @param borrowerSpending - The Borrower's spending balance.
     */
    async function assertTransferParts(
      tx: Awaited<ReturnType<typeof prepareConfidentialLoanPay>>,
      borrowerSpending: string,
    ): Promise<void> {
      const balance = {
        publicKey: BORROWER.publicKey,
        balanceCommitment: tx.BalanceCommitment,
        balanceCiphertext: borrowerSpending,
        contextHash: payContextHash,
      }
      // Part 1: the payment transfer, as an XLS-96 Send.
      await assertSendProof(tx.ZKProof.slice(0, SEND), {
        ...balance,
        recipients: [
          {
            publicKey: BORROWER.publicKey,
            ciphertext: tx.SenderEncryptedAmount,
          },
          {
            publicKey: BROKER.publicKey,
            ciphertext: tx.DestinationEncryptedAmount,
          },
          { publicKey: ISSUER.publicKey, ciphertext: tx.IssuerEncryptedAmount },
          {
            publicKey: AUDITOR.publicKey,
            ciphertext: tx.AuditorEncryptedAmount,
          },
        ],
        amountCommitment: tx.AmountCommitment,
      })
      // Part 2: the Loan Auditor's copy of the payment.
      assert.isTrue(
        await verifySendSigmaProof(tx.ZKProof.slice(SEND, SEND + SIGMA), {
          ...balance,
          recipients: [
            {
              publicKey: LOAN_AUDITOR.publicKey,
              ciphertext: tx.LoanAuditorEncryptedAmount,
            },
          ],
          amountCommitment: tx.AmountCommitment,
        }),
      )
    }

    it('builds a regular payment whose every proof part verifies', async function () {
      const { client, borrowerSpending } = await payClient()
      const tx = await prepareConfidentialLoanPay(client, {
        account: BORROWER_ADDRESS,
        loanID: LOAN_ID,
        amount: 100n,
        borrowerKeypair: BORROWER,
        amountOwed: terms.amountOwed,
        periodicPayment: terms.periodicPayment,
      })
      assert.isUndefined(tx.Flags)
      assert.lengthOf(tx.ZKProof, 2148 * 2)
      assertEncodable(tx)
      await assertTransferParts(tx, borrowerSpending)

      const loan = await fetchLoan(client)
      const [owedPart, periodicPart, range] = split(
        tx.ZKProof.slice(SEND + SIGMA),
        [LINK, LINK, RANGE],
      )
      // Parts 3-4: the commitments commit to the Amount Owed and Periodic Payment.
      assert.isTrue(
        await verifyConvertBackSigmaProof(owedPart, {
          publicKey: BORROWER.publicKey,
          ciphertext: loan.BorrowerEncryptedAmountOwed,
          commitment: tx.AmountOwedCommitment!,
          contextHash: payContextHash,
        }),
      )
      assert.isTrue(
        await verifyConvertBackSigmaProof(periodicPart, {
          publicKey: BORROWER.publicKey,
          ciphertext: loan.BorrowerEncryptedPeriodicPayment,
          commitment: tx.PeriodicPaymentCommitment!,
          contextHash: payContextHash,
        }),
      )
      // Part 5: Periodic Payment <= X <= Amount Owed.
      assert.isTrue(
        await verifyAggregatedRangeProof(
          range,
          [
            await combine([
              [tx.AmountCommitment, 1],
              [tx.PeriodicPaymentCommitment!, -1],
            ]),
            await combine([
              [tx.AmountOwedCommitment!, 1],
              [tx.AmountCommitment, -1],
            ]),
          ],
          payContextHash,
        ),
      )
      // The Broker reads the payment from its inbox credit.
      assert.strictEqual(
        await decryptAmount(
          tx.DestinationEncryptedAmount,
          BROKER.privateKey,
          1000n,
        ),
        100n,
      )
    })

    it('decrypts the terms itself when they are not given', async function () {
      const { client } = await payClient()
      const tx = await prepareConfidentialLoanPay(client, {
        account: BORROWER_ADDRESS,
        loanID: LOAN_ID,
        amount: 60n,
        borrowerKeypair: BORROWER,
      })
      assert.isString(tx.AmountOwedCommitment)
      assert.lengthOf(tx.ZKProof, 2148 * 2)
    })

    it('builds a full payment whose every proof part verifies', async function () {
      const { client, borrowerSpending } = await payClient()
      const tx = await prepareConfidentialLoanPay(client, {
        account: BORROWER_ADDRESS,
        loanID: LOAN_ID,
        amount: terms.amountOwed,
        borrowerKeypair: BORROWER,
        amountOwed: terms.amountOwed,
      })
      assert.strictEqual(tx.Flags, ConfidentialLoanPayFlags.tfLoanFullPayment)
      assert.isUndefined(tx.AmountOwedCommitment)
      assert.lengthOf(tx.ZKProof, 1202 * 2)
      assertEncodable(tx)
      await assertTransferParts(tx, borrowerSpending)

      // Part 3: the payment equals the Amount Owed.
      const loan = await fetchLoan(client)
      assert.isTrue(
        await verifyClawbackProof(
          tx.ZKProof.slice(SEND + SIGMA),
          0n,
          BORROWER.publicKey,
          await subtractCiphertexts(
            tx.SenderEncryptedAmount,
            loan.BorrowerEncryptedAmountOwed,
          ),
          payContextHash,
        ),
      )
    })

    it('rejects payments the ledger would refuse', async function () {
      const { client } = await payClient()
      const base = {
        account: BORROWER_ADDRESS,
        loanID: LOAN_ID,
        borrowerKeypair: BORROWER,
        amountOwed: terms.amountOwed,
        periodicPayment: terms.periodicPayment,
      }
      await expectXrplError(
        prepareConfidentialLoanPay(client, { ...base, amount: 59n }),
        /between the Periodic Payment 60 and the Amount Owed 660/u,
      )
      await expectXrplError(
        prepareConfidentialLoanPay(client, {
          ...base,
          amount: 100n,
          fullPayment: true,
        }),
        /must be the Amount Owed 660/u,
      )
      await expectXrplError(
        prepareConfidentialLoanPay(client, { ...base, amount: 2001n }),
        /exceeds the confidential spending balance/u,
      )
      await expectXrplError(
        prepareConfidentialLoanPay(client, {
          ...base,
          amount: 100n,
          amountOwed: 661n,
        }),
        /encrypted term is not 661/u,
      )
      await expectXrplError(
        prepareConfidentialLoanPay(client, {
          ...base,
          amount: 100n,
          borrowerKeypair: BROKER,
        }),
        /registered encryption key/u,
      )
      await expectXrplError(
        prepareConfidentialLoanPay(client, {
          ...base,
          account: OWNER,
          amount: 100n,
        }),
        /is not owed by/u,
      )

      const last = await payClient(1)
      await expectXrplError(
        prepareConfidentialLoanPay(last.client, { ...base, amount: 100n }),
        /last payment on a Loan must be a full payment/u,
      )
    })
  })
})
