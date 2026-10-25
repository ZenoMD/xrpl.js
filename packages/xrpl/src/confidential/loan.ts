/* eslint-disable max-lines, max-lines-per-function, max-params -- cohesive proof-assembly flows over many inputs */
import { type Client } from '../client'
import { XrplError } from '../errors'
import { Loan, LoanFlags, MPToken } from '../models/ledger'
import {
  ConfidentialLoanPay,
  ConfidentialLoanPayFlags,
  LoanSet,
} from '../models/transactions'
import { isFlagEnabled } from '../models/utils'

import {
  assertConfidentialAmount,
  decryptBound,
  fetchMPToken,
  resolveLedgerIndex,
  resolveSequence,
  resolveSpendingState,
} from './ledger'
import {
  fetchEntry,
  fetchLendingContext,
  LendingContext,
  requireBrokerKeypair,
} from './lending'
import {
  getConfidentialLoanPayContextHash,
  getLoanSetContextHash,
} from './lendingContext'
import { loadMptCrypto, type MptCryptoModule } from './loader'
import {
  ConfidentialKeypair,
  ConfidentialLoanPayParams,
  ConfidentialLoanSetParams,
} from './types'

// A Send proof's participants: sender, destination, issuer and MPT Auditor. The
// Loan Auditor's ciphertext follows them and is proved separately.
const SEND_PARTICIPANTS = 4

/** A confidential balance's witness for a proof of its ownership. */
interface BalanceWitness {
  commitment: string
  amount: bigint
  ciphertext: string
  blindingFactor: string
}

/** A recipient of a Send-style proof: a key and the ciphertext under it. */
interface Recipient {
  publicKey: string
  ciphertext: string
}

/** The inputs every proof over one balance holder's witness shares. */
interface Prover {
  crypto: MptCryptoModule
  keypair: ConfidentialKeypair
  witness: BalanceWitness
  contextHash: string
}

/** One term's ciphertexts and commitment, which share one randomness. */
interface EncryptedTerm {
  value: bigint
  blindingFactor: string
  ciphertexts: string[]
  commitment: string
}

/**
 * Decrypt a confidential spending balance and commit to it, forming the
 * witness the Send and Send-sigma proofs bind.
 *
 * @param crypto - The loaded mpt-crypto module.
 * @param spending - The `ConfidentialBalanceSpending` ciphertext.
 * @param keypair - The balance holder's keypair.
 * @param bound - The decrypt search bound.
 * @returns The balance witness.
 */
async function balanceWitness(
  crypto: MptCryptoModule,
  spending: string,
  keypair: ConfidentialKeypair,
  bound: bigint,
): Promise<BalanceWitness> {
  const [amount, blindingFactor] = await Promise.all([
    crypto.decryptAmount(spending, keypair.privateKey, bound),
    crypto.generateBlindingFactor(),
  ])
  return {
    commitment: await crypto.getPedersenCommitment(amount, blindingFactor),
    amount,
    ciphertext: spending,
    blindingFactor,
  }
}

/**
 * Encrypt a term under several keys with a fresh shared randomness, and commit
 * to it with the same randomness.
 *
 * @param crypto - The loaded mpt-crypto module.
 * @param value - The term.
 * @param keys - The public keys.
 * @returns The ciphertexts, in key order, and the commitment.
 */
async function encryptTerm(
  crypto: MptCryptoModule,
  value: bigint,
  keys: string[],
): Promise<EncryptedTerm> {
  const blindingFactor = await crypto.generateBlindingFactor()
  const [commitment, ...ciphertexts] = await Promise.all([
    crypto.getPedersenCommitment(value, blindingFactor),
    ...keys.map(async (key) =>
      crypto.encryptAmount(value, key, blindingFactor),
    ),
  ])
  return { value, blindingFactor, ciphertexts, commitment }
}

/**
 * Pair a term's ciphertexts with the keys they are under.
 *
 * @param keys - The public keys.
 * @param term - The term, encrypted under `keys` in order.
 * @returns The recipients.
 */
function recipients(keys: string[], term: EncryptedTerm): Recipient[] {
  return keys.map((publicKey, index) => ({
    publicKey,
    ciphertext: term.ciphertexts[index],
  }))
}

/**
 * The XLS-96 ConfidentialMPTSend proof of a term's transfer to `participants`.
 *
 * @param prover - The sender's proving inputs.
 * @param term - The amount transferred.
 * @param participants - The sender, destination, issuer and MPT Auditor.
 * @returns The 946-byte hex proof.
 */
async function sendProof(
  prover: Prover,
  term: EncryptedTerm,
  participants: Recipient[],
): Promise<string> {
  return prover.crypto.getConfidentialSendProof({
    privateKey: prover.keypair.privateKey,
    publicKey: prover.keypair.publicKey,
    amount: term.value,
    participants,
    txBlindingFactor: term.blindingFactor,
    contextHash: prover.contextHash,
    amountCommitment: term.commitment,
    balanceParams: prover.witness,
  })
}

/**
 * The XLS-96 Send sigma proof that a term's ciphertexts to `targets` encrypt the
 * value of its commitment.
 *
 * @param prover - The balance holder's proving inputs.
 * @param term - The term.
 * @param targets - The recipients the proof covers.
 * @returns The 192-byte hex proof.
 */
async function sigmaProof(
  prover: Prover,
  term: EncryptedTerm,
  targets: Recipient[],
): Promise<string> {
  return prover.crypto.getSendSigmaProof({
    privateKey: prover.keypair.privateKey,
    publicKey: prover.keypair.publicKey,
    amount: term.value,
    blindingFactor: term.blindingFactor,
    recipients: targets,
    amountCommitment: term.commitment,
    balanceParams: prover.witness,
    contextHash: prover.contextHash,
  })
}

/**
 * Check a confidential Loan's terms before proving them, so a proof the ledger
 * would reject is never built.
 *
 * @param params - The LoanSet inputs.
 * @param lendingBalance - The decrypted spendable Lending Balance.
 * @throws {XrplError} If the terms are inconsistent.
 */
function assertLoanTerms(
  params: ConfidentialLoanSetParams,
  lendingBalance: bigint,
): void {
  const { principal, amountOwed, periodicPayment, paymentTotal } = params
  assertConfidentialAmount(principal, false)
  assertConfidentialAmount(amountOwed, false)
  assertConfidentialAmount(periodicPayment, false)
  if (!Number.isInteger(paymentTotal) || paymentTotal < 1) {
    throw new XrplError('paymentTotal must be a positive integer')
  }
  if (amountOwed < principal) {
    throw new XrplError('amountOwed must be at least the principal')
  }
  if (BigInt(paymentTotal) * periodicPayment < amountOwed) {
    throw new XrplError(
      'paymentTotal * periodicPayment must be at least amountOwed',
    )
  }
  if (principal > lendingBalance) {
    throw new XrplError(
      `Principal ${principal.toString()} exceeds the spendable Lending Balance ${lendingBalance.toString()}`,
    )
  }
}

/**
 * Read the Borrower's registered encryption key for the Vault asset.
 *
 * @param token - The Borrower's MPToken.
 * @param borrower - The Borrower's address, for the error message.
 * @returns The Borrower's key.
 * @throws {XrplError} If the Borrower has no confidential balance.
 */
function requireBorrowerKey(token: MPToken, borrower: string): string {
  if (token.HolderEncryptionKey == null) {
    throw new XrplError(
      `Borrower ${borrower} has no confidential balance for the Vault asset`,
    )
  }
  return token.HolderEncryptionKey
}

/**
 * Build a LoanSet transaction that creates a confidential Loan from a
 * confidential LoanBroker. The principal moves from the Lending Balance to the
 * Borrower's confidential inbox as a ConfidentialMPTSend, and the principal,
 * Amount Owed and Periodic Payment are encrypted under the Borrower, Broker and
 * Loan Auditor keys. The Broker builds the proof; the other party adds
 * `CounterpartySignature` with `signLoanSetByCounterparty` before submission.
 *
 * @param client - A connected Client.
 * @param params - The loan inputs.
 * @returns The assembled, unsigned LoanSet transaction.
 * @throws {XrplError} If the LoanBroker is not confidential, the Borrower has no
 * confidential balance, a key is missing, or the terms are inconsistent.
 */
export async function prepareConfidentialLoanSet(
  client: Client,
  params: ConfidentialLoanSetParams,
): Promise<LoanSet> {
  const [crypto, ledgerIndex] = await Promise.all([
    loadMptCrypto(),
    resolveLedgerIndex(client, params.ledgerIndex),
  ])
  const [lending, sequence] = await Promise.all([
    fetchLendingContext(client, params.loanBrokerID, ledgerIndex),
    resolveSequence(client, params.account, params.sequence),
  ])
  requireBrokerKeypair(lending, params.brokerKeypair)
  const owner = lending.broker.Owner
  if (params.account !== owner && params.account !== params.borrower) {
    throw new XrplError(
      'LoanSet must be submitted by the LoanBroker owner or the Borrower',
    )
  }
  const borrowerKey = requireBorrowerKey(
    await fetchMPToken(
      client,
      params.borrower,
      lending.mptIssuanceID,
      ledgerIndex,
    ),
    params.borrower,
  )
  const { spending, version } = resolveSpendingState(
    lending.lendingBalance,
    lending.broker.Account,
  )
  const witness = await balanceWitness(
    crypto,
    spending,
    params.brokerKeypair,
    decryptBound(lending.issuance),
  )
  assertLoanTerms(params, witness.amount)

  const prover: Prover = {
    crypto,
    keypair: params.brokerKeypair,
    witness,
    contextHash: getLoanSetContextHash(
      lending.broker.Account,
      lending.mptIssuanceID,
      sequence,
      params.borrower,
      version,
    ),
  }
  const { principal, owed, periodic, zkProof } = await loanSetProof(
    prover,
    lending,
    borrowerKey,
    params,
  )

  const tx: LoanSet = {
    TransactionType: 'LoanSet',
    Account: params.account,
    Sequence: sequence,
    LoanBrokerID: params.loanBrokerID,
    Counterparty: params.account === owner ? params.borrower : owner,
    PaymentTotal: params.paymentTotal,
    SenderEncryptedAmount: principal.ciphertexts[0],
    DestinationEncryptedAmount: principal.ciphertexts[1],
    IssuerEncryptedAmount: principal.ciphertexts[2],
    AuditorEncryptedAmount: principal.ciphertexts[3],
    BalanceCommitment: witness.commitment,
    AmountCommitment: principal.commitment,
    ZKProof: zkProof,
    LoanAuditorEncryptionKey: params.loanAuditorKey,
    LoanAuditorEncryptedPrincipal: principal.ciphertexts[4],
    BorrowerEncryptedAmountOwed: owed.ciphertexts[0],
    BrokerEncryptedAmountOwed: owed.ciphertexts[1],
    LoanAuditorEncryptedAmountOwed: owed.ciphertexts[2],
    BorrowerEncryptedPeriodicPayment: periodic.ciphertexts[0],
    BrokerEncryptedPeriodicPayment: periodic.ciphertexts[1],
    LoanAuditorEncryptedPeriodicPayment: periodic.ciphertexts[2],
    AmountOwedCommitment: owed.commitment,
    PeriodicPaymentCommitment: periodic.commitment,
  }
  if (params.paymentInterval != null) {
    tx.PaymentInterval = params.paymentInterval
  }
  if (params.gracePeriod != null) {
    tx.GracePeriod = params.gracePeriod
  }
  if (params.data != null) {
    tx.Data = params.data
  }
  return tx
}

/**
 * Encrypt a confidential Loan's terms and build its proof (spec §11.2). Each
 * term's ciphertexts and commitment share one randomness, distinct from the
 * other terms'.
 *
 * @param prover - The Broker's proving inputs over the Lending Balance.
 * @param lending - The LoanBroker's lending context.
 * @param borrowerKey - The Borrower's encryption key.
 * @param params - The loan inputs.
 * @returns The encrypted terms and the 3030-byte hex proof.
 */
async function loanSetProof(
  prover: Prover,
  lending: LendingContext,
  borrowerKey: string,
  params: ConfidentialLoanSetParams,
): Promise<{
  principal: EncryptedTerm
  owed: EncryptedTerm
  periodic: EncryptedTerm
  zkProof: string
}> {
  const { crypto } = prover
  const brokerKey = prover.keypair.publicKey
  // Principal: sender, destination, issuer, MPT Auditor, Loan Auditor.
  const principalKeys = [
    brokerKey,
    borrowerKey,
    lending.issuerKey,
    lending.auditorKey,
    params.loanAuditorKey,
  ]
  // Amount Owed and Periodic Payment: Borrower, Broker, Loan Auditor.
  const termKeys = [borrowerKey, brokerKey, params.loanAuditorKey]
  const [principal, owed, periodic] = await Promise.all([
    encryptTerm(crypto, params.principal, principalKeys),
    encryptTerm(crypto, params.amountOwed, termKeys),
    encryptTerm(crypto, params.periodicPayment, termKeys),
  ])
  const principalRecipients = recipients(principalKeys, principal)
  const total = BigInt(params.paymentTotal)

  const parts = await Promise.all([
    // 1. The principal transfer, as in XLS-96 ConfidentialMPTSend.
    sendProof(
      prover,
      principal,
      principalRecipients.slice(0, SEND_PARTICIPANTS),
    ),
    // 2. The Loan Auditor's principal ciphertext encrypts P.
    sigmaProof(prover, principal, principalRecipients.slice(SEND_PARTICIPANTS)),
    // 3-4. The Amount Owed and Periodic Payment ciphertexts encrypt the values
    // of their commitments.
    sigmaProof(prover, owed, recipients(termKeys, owed)),
    sigmaProof(prover, periodic, recipients(termKeys, periodic)),
    // 5. O, Q >= 0.
    crypto.getAggregatedRangeProof(
      [owed.value, periodic.value],
      [owed.blindingFactor, periodic.blindingFactor],
      prover.contextHash,
    ),
    // 6. O >= P and N*Q >= O, over PC_O - PC_P and N*PC_Q - PC_O.
    crypto.getAggregatedRangeProof(
      [owed.value - principal.value, total * periodic.value - owed.value],
      [
        crypto.subtractScalars(owed.blindingFactor, principal.blindingFactor),
        crypto.subtractScalars(
          crypto.multiplyScalar(periodic.blindingFactor, total),
          owed.blindingFactor,
        ),
      ],
      prover.contextHash,
    ),
  ])
  return { principal, owed, periodic, zkProof: parts.join('') }
}

/**
 * Decrypt one of a Loan's Borrower-key terms: a claimed value is checked in
 * constant time, otherwise it is searched for up to `bound`.
 *
 * @param crypto - The loaded mpt-crypto module.
 * @param ciphertext - The term's Borrower-key ciphertext.
 * @param privateKey - The Borrower's private key.
 * @param claimed - The caller's claimed value, if any.
 * @param bound - The search bound.
 * @returns The term.
 * @throws {XrplError} If a claimed value does not match the ciphertext.
 */
async function decryptTerm(
  crypto: MptCryptoModule,
  ciphertext: string,
  privateKey: string,
  claimed: bigint | undefined,
  bound: bigint,
): Promise<bigint> {
  if (claimed == null) {
    return crypto.decryptAmount(ciphertext, privateKey, bound)
  }
  try {
    return await crypto.decryptAmount(ciphertext, privateKey, claimed, claimed)
  } catch {
    throw new XrplError(
      `The Loan's encrypted term is not ${claimed.toString()}`,
    )
  }
}

/** The ledger state a ConfidentialLoanPay is built from. */
interface LoanPayContext {
  loan: Loan
  lending: LendingContext
  borrowerToken: MPToken
  owedCiphertext: string
  periodicCiphertext: string
  loanAuditorKey: string
}

/**
 * Read a confidential Loan, its LoanBroker's lending context and the
 * Borrower's MPToken, checking the Loan is the account's to pay.
 *
 * @param client - A connected Client.
 * @param params - The payment inputs.
 * @param ledgerIndex - Ledger to read at.
 * @returns The payment context.
 * @throws {XrplError} If the Loan is not confidential or not the account's, or
 * `borrowerKeypair` is not the Borrower's key.
 */
async function fetchLoanPayContext(
  client: Client,
  params: ConfidentialLoanPayParams,
  ledgerIndex: ConfidentialLoanPayParams['ledgerIndex'],
): Promise<LoanPayContext> {
  const loan = await fetchEntry<Loan>(client, params.loanID, ledgerIndex)
  if (!isFlagEnabled(loan.Flags, LoanFlags.lsfLoanConfidential)) {
    throw new XrplError(`Loan ${params.loanID} is not confidential`)
  }
  if (loan.Borrower !== params.account) {
    throw new XrplError(
      `Loan ${params.loanID} is not owed by ${params.account}`,
    )
  }
  const {
    BorrowerEncryptedAmountOwed: owedCiphertext,
    BorrowerEncryptedPeriodicPayment: periodicCiphertext,
    LoanAuditorEncryptionKey: loanAuditorKey,
  } = loan
  if (
    owedCiphertext == null ||
    periodicCiphertext == null ||
    loanAuditorKey == null
  ) {
    throw new XrplError(`Loan ${params.loanID} has no encrypted terms`)
  }
  const lending = await fetchLendingContext(
    client,
    loan.LoanBrokerID,
    ledgerIndex,
  )
  const borrowerToken = await fetchMPToken(
    client,
    params.account,
    lending.mptIssuanceID,
    ledgerIndex,
  )
  if (
    requireBorrowerKey(borrowerToken, params.account).toUpperCase() !==
    params.borrowerKeypair.publicKey.toUpperCase()
  ) {
    throw new XrplError(
      'borrowerKeypair is not the Borrower’s registered encryption key',
    )
  }
  return {
    loan,
    lending,
    borrowerToken,
    owedCiphertext,
    periodicCiphertext,
    loanAuditorKey,
  }
}

/**
 * Build a ConfidentialLoanPay transaction that pays a confidential Loan from the
 * Borrower's confidential spending balance into the Lending Balance inbox. A
 * regular payment is at least the Periodic Payment and at most the Amount Owed;
 * a full payment is exactly the Amount Owed and closes the Loan.
 *
 * @param client - A connected Client.
 * @param params - The payment inputs.
 * @returns The assembled, unsigned ConfidentialLoanPay transaction.
 * @throws {XrplError} If the Loan is not confidential or not the account's, a
 * key is missing, or the payment is out of range.
 */
// eslint-disable-next-line max-statements -- the full and regular payments share one setup
export async function prepareConfidentialLoanPay(
  client: Client,
  params: ConfidentialLoanPayParams,
): Promise<ConfidentialLoanPay> {
  assertConfidentialAmount(params.amount, false)
  const [crypto, ledgerIndex] = await Promise.all([
    loadMptCrypto(),
    resolveLedgerIndex(client, params.ledgerIndex),
  ])
  const [context, sequence] = await Promise.all([
    fetchLoanPayContext(client, params, ledgerIndex),
    resolveSequence(client, params.account, params.sequence),
  ])
  const { loan, lending, borrowerToken } = context
  const { borrowerKeypair, amount } = params
  const { spending, version } = resolveSpendingState(
    borrowerToken,
    params.account,
  )
  const bound = params.decryptBound ?? decryptBound(lending.issuance)
  const [witness, owed] = await Promise.all([
    balanceWitness(
      crypto,
      spending,
      borrowerKeypair,
      decryptBound(lending.issuance),
    ),
    decryptTerm(
      crypto,
      context.owedCiphertext,
      borrowerKeypair.privateKey,
      params.amountOwed,
      bound,
    ),
  ])
  const full = isFullPayment(params, loan, owed, witness.amount)

  // Borrower (sender), Broker (destination), issuer, MPT Auditor, Loan Auditor.
  const keys = [
    borrowerKeypair.publicKey,
    lending.brokerKey,
    lending.issuerKey,
    lending.auditorKey,
    context.loanAuditorKey,
  ]
  const payment = await encryptTerm(crypto, amount, keys)
  const prover: Prover = {
    crypto,
    keypair: borrowerKeypair,
    witness,
    contextHash: getConfidentialLoanPayContextHash({
      borrower: params.account,
      mptIssuanceID: lending.mptIssuanceID,
      sequence,
      brokerPseudoAccount: lending.broker.Account,
      borrowerVersion: version,
      loanID: params.loanID,
      loanVersion: loan.ConfidentialLoanVersion ?? 0,
    }),
  }
  const paymentRecipients = recipients(keys, payment)
  const transferParts = await Promise.all([
    // 1. The payment transfer, as in XLS-96 ConfidentialMPTSend.
    sendProof(prover, payment, paymentRecipients.slice(0, SEND_PARTICIPANTS)),
    // 2. The Loan Auditor's ciphertext encrypts X.
    sigmaProof(prover, payment, paymentRecipients.slice(SEND_PARTICIPANTS)),
  ])

  const tx: ConfidentialLoanPay = {
    TransactionType: 'ConfidentialLoanPay',
    Account: params.account,
    Sequence: sequence,
    LoanID: params.loanID,
    SenderEncryptedAmount: payment.ciphertexts[0],
    DestinationEncryptedAmount: payment.ciphertexts[1],
    IssuerEncryptedAmount: payment.ciphertexts[2],
    AuditorEncryptedAmount: payment.ciphertexts[3],
    LoanAuditorEncryptedAmount: payment.ciphertexts[4],
    BalanceCommitment: witness.commitment,
    AmountCommitment: payment.commitment,
    ZKProof: '',
  }
  if (full) {
    tx.Flags = ConfidentialLoanPayFlags.tfLoanFullPayment
    tx.ZKProof = [
      ...transferParts,
      await fullPaymentProof(prover, payment, context.owedCiphertext),
    ].join('')
    return tx
  }
  const periodic = await decryptTerm(
    crypto,
    context.periodicCiphertext,
    borrowerKeypair.privateKey,
    params.periodicPayment,
    bound,
  )
  if (amount < periodic || amount > owed) {
    throw new XrplError(
      `A regular payment must be between the Periodic Payment ${periodic.toString()} and the Amount Owed ${owed.toString()}`,
    )
  }
  const regular = await regularPaymentProof(prover, payment, context, {
    owed,
    periodic,
  })
  tx.AmountOwedCommitment = regular.owedCommitment
  tx.PeriodicPaymentCommitment = regular.periodicCommitment
  tx.ZKProof = [...transferParts, regular.zkProof].join('')
  return tx
}

/**
 * Decide whether a payment is full or regular, checking it is one the ledger
 * accepts.
 *
 * @param params - The payment inputs.
 * @param loan - The confidential Loan.
 * @param owed - The decrypted Amount Owed.
 * @param balance - The Borrower's decrypted spending balance.
 * @returns Whether the payment is a full payment.
 * @throws {XrplError} If the payment exceeds the balance, a full payment is not
 * the Amount Owed, or a regular payment would be the last one.
 */
function isFullPayment(
  params: ConfidentialLoanPayParams,
  loan: Loan,
  owed: bigint,
  balance: bigint,
): boolean {
  const { amount } = params
  if (amount > balance) {
    throw new XrplError(
      `Payment ${amount.toString()} exceeds the confidential spending balance ${balance.toString()}`,
    )
  }
  const full = params.fullPayment ?? amount === owed
  if (full && amount !== owed) {
    throw new XrplError(
      `A full payment must be the Amount Owed ${owed.toString()}`,
    )
  }
  if (!full && loan.PaymentRemaining <= 1) {
    throw new XrplError('The last payment on a Loan must be a full payment')
  }
  return full
}

/**
 * Part 3 of a full payment's proof: X = Amount Owed, as an XLS-96 Clawback sigma
 * proof that `SenderEncryptedAmount - BorrowerEncryptedAmountOwed` encrypts 0.
 *
 * @param prover - The Borrower's proving inputs.
 * @param payment - The encrypted payment.
 * @param owedCiphertext - The Loan's `BorrowerEncryptedAmountOwed`.
 * @returns The 64-byte hex proof.
 */
async function fullPaymentProof(
  prover: Prover,
  payment: EncryptedTerm,
  owedCiphertext: string,
): Promise<string> {
  const { crypto, keypair } = prover
  const difference = await crypto.subtractCiphertexts(
    payment.ciphertexts[0],
    owedCiphertext,
  )
  return crypto.getClawbackProof(
    keypair.privateKey,
    keypair.publicKey,
    prover.contextHash,
    BigInt(0),
    difference,
  )
}

/**
 * An XLS-96 ConvertBack sigma proof that `commitment` commits to the value of
 * `ciphertext`, which the prover can decrypt.
 *
 * @param prover - The holder's proving inputs.
 * @param value - The ciphertext's value.
 * @param blindingFactor - The commitment's blinding factor.
 * @param ciphertext - The ciphertext under the prover's key.
 * @param commitment - The commitment to `value`.
 * @returns The 128-byte hex proof.
 */
async function linkProof(
  prover: Prover,
  value: bigint,
  blindingFactor: string,
  ciphertext: string,
  commitment: string,
): Promise<string> {
  return prover.crypto.getConvertBackSigmaProof({
    privateKey: prover.keypair.privateKey,
    publicKey: prover.keypair.publicKey,
    balanceParams: { commitment, amount: value, ciphertext, blindingFactor },
    contextHash: prover.contextHash,
  })
}

/**
 * Parts 3-5 of a regular payment's proof: fresh commitments to the Amount Owed
 * and Periodic Payment, ConvertBack sigma proofs linking them to the Loan's
 * ciphertexts, and a range proof that Periodic Payment <= X <= Amount Owed.
 *
 * @param prover - The Borrower's proving inputs.
 * @param payment - The encrypted payment.
 * @param context - The payment context.
 * @param terms - The decrypted Amount Owed and Periodic Payment.
 * @param terms.owed - The Amount Owed.
 * @param terms.periodic - The Periodic Payment.
 * @returns The commitments and the concatenated hex proof parts.
 */
async function regularPaymentProof(
  prover: Prover,
  payment: EncryptedTerm,
  context: LoanPayContext,
  terms: { owed: bigint; periodic: bigint },
): Promise<{
  owedCommitment: string
  periodicCommitment: string
  zkProof: string
}> {
  const { crypto } = prover
  const [rhoO, rhoQ] = await Promise.all([
    crypto.generateBlindingFactor(),
    crypto.generateBlindingFactor(),
  ])
  const [owedCommitment, periodicCommitment] = await Promise.all([
    crypto.getPedersenCommitment(terms.owed, rhoO),
    crypto.getPedersenCommitment(terms.periodic, rhoQ),
  ])
  const parts = await Promise.all([
    // 3-4. The commitments commit to the Amount Owed and Periodic Payment.
    linkProof(prover, terms.owed, rhoO, context.owedCiphertext, owedCommitment),
    linkProof(
      prover,
      terms.periodic,
      rhoQ,
      context.periodicCiphertext,
      periodicCommitment,
    ),
    // 5. Periodic Payment <= X <= Amount Owed, over PC_X - PC_Q and PC_O - PC_X.
    crypto.getAggregatedRangeProof(
      [payment.value - terms.periodic, terms.owed - payment.value],
      [
        crypto.subtractScalars(payment.blindingFactor, rhoQ),
        crypto.subtractScalars(rhoO, payment.blindingFactor),
      ],
      prover.contextHash,
    ),
  ])
  return { owedCommitment, periodicCommitment, zkProof: parts.join('') }
}
