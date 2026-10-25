/**
 * Parameter types for the high-level Confidential MPT (XLS-0096) builders. Every
 * byte field is an uppercase, even-length hex string (no `0x` prefix); integer
 * amounts are `bigint` to losslessly carry the full `uint64_t` range.
 */

import type { LedgerIndex } from '../models/common'
import type { SubmittableTransaction } from '../models/transactions'

/**
 * A predicted confidential spending balance a proof is built against. Inside a
 * Batch, an earlier balance-mutating inner for the same `(account, token)` leaves
 * state the ledger does not yet reflect; {@link prepareConfidentialBatch} predicts
 * it and threads it into the next proof-bearing builder via `confidentialState`.
 * Standalone callers never set this — the builder reads live ledger state.
 */
export interface ConfidentialSpendingState {
  /** The 66-byte hex `ConfidentialBalanceSpending` ciphertext to prove against. */
  spending: string
  /** The `ConfidentialBalanceVersion` the proof binds. */
  version: number
}

/**
 * An ElGamal keypair used to encrypt to, and decrypt from, a confidential MPT
 * balance: a 32-byte hex private key and the matching 33-byte hex public key.
 */
export interface ConfidentialKeypair {
  privateKey: string
  publicKey: string
}

/** Inputs shared by every confidential builder. */
interface BaseConfidentialParams {
  /** The 24-byte hex MPTokenIssuanceID. */
  mptIssuanceID: string
  /**
   * Optional explicit sequence number. When omitted the builder queries the
   * account's current sequence. The returned transaction pins `Sequence`, so it
   * must be submitted without re-deriving the sequence (the proof is bound to it).
   */
  sequence?: number
  /**
   * Advanced: the ledger index to read confidential state (balance, version,
   * issuer/auditor keys) from, so a single proof is built from one coherent
   * ledger snapshot. Defaults to the latest validated ledger.
   * {@link prepareConfidentialBatch} sets it so every inner shares one ledger;
   * standalone callers normally omit it.
   */
  ledgerIndex?: LedgerIndex
}

/** Inputs for {@link prepareConfidentialConvert}. */
export interface ConfidentialConvertParams extends BaseConfidentialParams {
  /** The converting holder's classic XRPL address. */
  account: string
  /** The public MPT amount being moved into the confidential balance. */
  amount: bigint
  /** The holder's ElGamal keypair. */
  holderKeypair: ConfidentialKeypair
  /**
   * Whether to register the holder's encryption key on this transaction. By
   * default the builder registers it exactly when the ledger has no holder key
   * yet — required on the first conversion, rejected as a duplicate on later
   * ones — so this normally never needs to be set explicitly.
   */
  registerKey?: boolean
}

/** Inputs for {@link prepareConfidentialConvertBack}. */
export interface ConfidentialConvertBackParams extends BaseConfidentialParams {
  /** The holder's classic XRPL address. */
  account: string
  /** The public MPT amount being revealed from the confidential balance. */
  amount: bigint
  /** The holder's ElGamal keypair. */
  holderKeypair: ConfidentialKeypair
  /**
   * Advanced: predicted spending balance + version to prove against, overriding
   * live ledger state. Set by {@link prepareConfidentialBatch}; unset for a
   * standalone convert-back.
   */
  confidentialState?: ConfidentialSpendingState
  /**
   * Advanced: extra headroom for the balance-decrypt search bound over the
   * issuance's on-ledger `ConfidentialOutstandingAmount`. Set by
   * {@link prepareConfidentialBatch} to the in-batch Convert total, so a balance
   * topped up earlier in the same Batch stays decryptable; unset otherwise.
   */
  outstandingDelta?: bigint
}

/** Inputs for {@link prepareConfidentialSend}. */
export interface ConfidentialSendParams extends BaseConfidentialParams {
  /** The sender's classic XRPL address. */
  account: string
  /** The destination's classic XRPL address. */
  destination: string
  /** The confidential MPT amount being transferred. */
  amount: bigint
  /** The sender's ElGamal keypair. */
  senderKeypair: ConfidentialKeypair
  /** Optional destination tag. */
  destinationTag?: number
  /** Optional credential IDs to satisfy the destination's deposit auth. */
  credentialIDs?: string[]
  /**
   * Advanced: predicted spending balance + version to prove against, overriding
   * live ledger state. Set by {@link prepareConfidentialBatch} to chain multiple
   * same-`(account, token)` transactions in one Batch; unset for a standalone send.
   */
  confidentialState?: ConfidentialSpendingState
  /**
   * Advanced: the destination's ElGamal public key, overriding the on-ledger
   * lookup. Set by {@link prepareConfidentialBatch} when an earlier same-batch
   * Convert registers the destination's key (so it is not yet on-ledger); unset
   * for a standalone send, which reads it from the destination's MPToken.
   */
  destinationKey?: string
  /**
   * Advanced: extra headroom for the balance-decrypt search bound over the
   * issuance's on-ledger `ConfidentialOutstandingAmount`. Set by
   * {@link prepareConfidentialBatch} to the in-batch Convert total, so a balance
   * topped up earlier in the same Batch stays decryptable; unset otherwise.
   */
  outstandingDelta?: bigint
}

/** Inputs for {@link prepareConfidentialClawback}. */
export interface ConfidentialClawbackParams extends BaseConfidentialParams {
  /** The issuer's classic XRPL address. */
  account: string
  /** The holder whose confidential balance is being clawed back. */
  holder: string
  /** The issuer's ElGamal keypair. */
  issuerKeypair: ConfidentialKeypair
  /**
   * The holder's full confidential balance, supplied to skip the (potentially
   * slow) on-ledger decryption. Confidential clawback is all-or-nothing: rippled
   * always burns the holder's entire confidential balance and the proof binds
   * this value to the issuer-encrypted balance ciphertext, so it MUST equal the
   * full balance — a smaller value does not claw back a partial amount, it just
   * produces a proof rippled rejects (tecBAD_PROOF). When omitted, the builder
   * decrypts the issuer-encrypted balance to recover the full amount itself.
   */
  amount?: bigint
  /**
   * Advanced: predicted issuer-encrypted balance to prove against, overriding live
   * ledger state. Set by {@link prepareConfidentialBatch} when an earlier same-batch
   * inner changed the holder's balance; unset for a standalone clawback.
   */
  issuerEncryptedBalanceOverride?: string
  /**
   * Advanced: extra headroom for the balance-decrypt search bound over the
   * issuance's on-ledger `ConfidentialOutstandingAmount`. Set by
   * {@link prepareConfidentialBatch} to the in-batch Convert total; unset otherwise.
   */
  outstandingDelta?: bigint
}

/** Inputs for {@link prepareConfidentialMergeInbox}. */
export interface ConfidentialMergeInboxParams extends BaseConfidentialParams {
  /** The holder's classic XRPL address. */
  account: string
}

/**
 * Inputs shared by the Confidential Lending Protocol builders. Unlike the
 * Confidential MPT builders these take no `mptIssuanceID`: the issuance is the
 * Vault's asset, which the builder reads from the ledger.
 */
interface BaseLendingParams {
  /** The LoanBroker owner's classic XRPL address (the submitting account). */
  account: string
  /** See {@link BaseConfidentialParams.sequence}. */
  sequence?: number
  /** See {@link BaseConfidentialParams.ledgerIndex}. */
  ledgerIndex?: LedgerIndex
}

/** Inputs for {@link prepareConfidentialLoanBrokerSet}. */
export interface ConfidentialLoanBrokerSetParams extends BaseLendingParams {
  /** The ID of the Vault the LoanBroker lends from. Its asset must be an MPT. */
  vaultID: string
  /**
   * The Broker Key: the ElGamal keypair the Lending Balance is encrypted under.
   * Persist the private key — it is the only thing that can decrypt the
   * Lending Balance and is needed to fund loans from it.
   */
  brokerKeypair: ConfidentialKeypair
  /** Optional arbitrary hex metadata (`Data`). */
  data?: string
  /** Optional `DebtMaximum`, limiting the amount the broker can draw. */
  debtMaximum?: string
}

/** Inputs for {@link prepareLoanBrokerDraw}. */
export interface LoanBrokerDrawParams extends BaseLendingParams {
  /** The confidential LoanBroker drawing from its Vault. */
  loanBrokerID: string
  /** The MPT amount to draw into the Lending Balance inbox. */
  amount: bigint
}

/** Inputs for {@link prepareLoanBrokerSettle}. */
export interface LoanBrokerSettleParams extends BaseLendingParams {
  /** The confidential LoanBroker settling to its Vault. */
  loanBrokerID: string
  /** The MPT amount to return from the spendable Lending Balance. */
  amount: bigint
  /** The Broker Key, which decrypts the Lending Balance to prove the settle. */
  brokerKeypair: ConfidentialKeypair
}

/** Inputs for {@link prepareLoanBrokerMergeInbox}. */
export interface LoanBrokerMergeInboxParams extends BaseLendingParams {
  /** The confidential LoanBroker whose Lending Balance inbox is merged. */
  loanBrokerID: string
}

/** Inputs for {@link prepareConfidentialLoanSet}. */
export interface ConfidentialLoanSetParams extends BaseLendingParams {
  /**
   * The submitting account: the LoanBroker owner or the Borrower. The other
   * party becomes `Counterparty` and co-signs (`signLoanSetByCounterparty`).
   * Either way the Broker builds the proof, which binds this account's sequence.
   */
  account: string
  /** The confidential LoanBroker lending from its Lending Balance. */
  loanBrokerID: string
  /** The Borrower's classic address. It must hold a confidential balance. */
  borrower: string
  /** The Broker Key, which decrypts the Lending Balance to prove the loan. */
  brokerKeypair: ConfidentialKeypair
  /** The Loan Auditor's ElGamal public key, agreed by Broker and Borrower. */
  loanAuditorKey: string
  /** The principal moved to the Borrower's inbox. */
  principal: bigint
  /** The Amount Owed: at least the principal. */
  amountOwed: bigint
  /** The Periodic Payment: `paymentTotal * periodicPayment` must cover `amountOwed`. */
  periodicPayment: bigint
  /** The number of payments (`PaymentTotal`). */
  paymentTotal: number
  /** Optional `PaymentInterval` in seconds. */
  paymentInterval?: number
  /** Optional `GracePeriod` in seconds. */
  gracePeriod?: number
  /** Optional arbitrary hex metadata (`Data`). */
  data?: string
}

/** Inputs for {@link prepareConfidentialLoanPay}. */
export interface ConfidentialLoanPayParams extends BaseLendingParams {
  /** The Borrower's classic address (the submitting account). */
  account: string
  /** The confidential Loan being paid. */
  loanID: string
  /** The payment. */
  amount: bigint
  /** The Borrower's ElGamal keypair. */
  borrowerKeypair: ConfidentialKeypair
  /**
   * Whether this is a full payment (`tfLoanFullPayment`) of the whole Amount
   * Owed, closing the Loan. Defaults to `amount === amountOwed`.
   */
  fullPayment?: boolean
  /**
   * The Loan's current Amount Owed, if known. The builder checks it against the
   * Loan's ciphertext in constant time instead of searching for it; without it,
   * the search is bounded by `decryptBound` and costs O(bound).
   */
  amountOwed?: bigint
  /** The Loan's Periodic Payment, if known (checked as `amountOwed` is). */
  periodicPayment?: bigint
  /**
   * The search bound for decrypting terms not given above. Defaults to the
   * issuance's `ConfidentialOutstandingAmount`, which may be below an Amount
   * Owed that includes interest — pass the terms instead where possible.
   */
  decryptBound?: bigint
}

/** A confidential LoanBroker's decrypted Lending Balance. */
export interface LendingBalance {
  /** The spendable balance (`ConfidentialBalanceSpending`). */
  spending: bigint
  /** Drawn funds not yet merged into the spendable balance. */
  inbox: bigint
}

/**
 * One confidential operation in a {@link ConfidentialBatchParams} inner list: a
 * build *recipe*, not a transaction — the assembler builds the ciphertexts and
 * zero-knowledge proof from it. Discriminated by `operation`; each variant is the matching
 * standalone builder's inputs minus the fields the assembler owns (`sequence` and
 * the internal predicted-state overrides), so if you know `prepareConfidentialSend`
 * you know `{ operation: 'send', ... }`.
 */
export type ConfidentialBatchOperation =
  | ({ operation: 'convert' } & Omit<
      ConfidentialConvertParams,
      'sequence' | 'ledgerIndex'
    >)
  | ({ operation: 'convertBack' } & Omit<
      ConfidentialConvertBackParams,
      'sequence' | 'ledgerIndex' | 'confidentialState' | 'outstandingDelta'
    >)
  | ({ operation: 'send' } & Omit<
      ConfidentialSendParams,
      | 'sequence'
      | 'ledgerIndex'
      | 'confidentialState'
      | 'destinationKey'
      | 'outstandingDelta'
    >)
  | ({ operation: 'mergeInbox' } & Omit<
      ConfidentialMergeInboxParams,
      'sequence' | 'ledgerIndex'
    >)
  | ({ operation: 'clawback' } & Omit<
      ConfidentialClawbackParams,
      | 'sequence'
      | 'ledgerIndex'
      | 'amount'
      | 'issuerEncryptedBalanceOverride'
      | 'outstandingDelta'
    >)

/**
 * A single inner of a confidential Batch, in one of two intentionally distinct
 * shapes:
 *
 * - a **confidential operation spec** ({@link ConfidentialBatchOperation}) — a *recipe*
 *   the assembler builds into a transaction and proof. `operation`-tagged and camelCase
 *   because it mirrors a builder's parameters (e.g. `senderKeypair`), not a
 *   serialized transaction.
 * - a **ready-made transaction** (a {@link SubmittableTransaction}) — already
 *   the wire model, so `TransactionType`-tagged and PascalCase. The assembler only
 *   shapes it as a Batch inner (`tfInnerBatchTxn`, `Fee: '0'`, a sequence) and
 *   passes it through.
 *
 * The two read differently on purpose: `operation` means "build this for me",
 * `TransactionType` means "here is a finished transaction".
 */
export type ConfidentialBatchInner =
  ConfidentialBatchOperation | SubmittableTransaction

/** Inputs for {@link prepareConfidentialBatch}. */
export interface ConfidentialBatchParams {
  /** The account that signs and owns the outer Batch (pays the outer fee). */
  account: string
  /**
   * The inner transactions in execution order. Array order is the on-ledger apply
   * order: the assembler assigns each inner its position-derived sequence and threads
   * predicted balance state through same-`(account, token)` operations.
   */
  inners: ConfidentialBatchInner[]
  /** Outer Batch flags. Defaults to `tfAllOrNothing` (atomic). */
  batchFlags?: number
  /**
   * Extra signatures the outer fee must cover, forwarded to `client.autofill`: the
   * outer account's own multisign signers, plus one for each co-signing participant
   * (or that participant's signer count when multisigned). Omit for a
   * single-signed, single-account Batch.
   */
  signersCount?: number
  /**
   * Extra signatures the outer fee must cover for a multisigned sponsor, forwarded
   * to `client.autofill`: the signer count of the outer Batch's `SponsorSignature`.
   * Omit when not sponsored, or when the sponsor signs with a single key.
   */
  sponsorSignersCount?: number
}
