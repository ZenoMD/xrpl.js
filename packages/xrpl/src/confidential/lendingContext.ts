/**
 * Context hashes the Confidential Lending Protocol proofs are bound to. Each
 * reuses an XLS-96 context-hash layout with a lending transaction type, which
 * the mpt-crypto WASM hard-codes — so they are computed here rather than there.
 * Every layout starts with `TxType || Account || MPTokenIssuanceID || Sequence`.
 */
import sha512Half from '../utils/hashes/sha512Half'

import { accountIdHex } from './ledger'

// rippled transaction types bound into the context hashes.
const LOAN_BROKER_SET_TX_TYPE = 74
const LOAN_SET_TX_TYPE = 80
const LOAN_BROKER_SETTLE_TX_TYPE = 83
const CONFIDENTIAL_LOAN_PAY_TX_TYPE = 99

const UINT16_BYTES = 2
const UINT32_BYTES = 4
const HEX_RADIX = 16

/**
 * Hex-encode an unsigned integer big-endian in `bytes` bytes.
 *
 * @param value - The integer to encode.
 * @param bytes - The encoded width.
 * @returns The uppercase hex encoding.
 */
function uintHex(value: number, bytes: number): string {
  return value
    .toString(HEX_RADIX)
    .toUpperCase()
    .padStart(bytes * 2, '0')
}

/**
 * Hash the common context prefix followed by a transaction-specific suffix.
 *
 * @param txType - The rippled transaction type.
 * @param account - The classic address the proof is built for.
 * @param mptIssuanceID - The 24-byte hex issuance ID.
 * @param sequence - The transaction's `Sequence` (or `TicketSequence`).
 * @param suffix - The hex-encoded remainder of the layout.
 * @returns The 32-byte hex context hash.
 */
// eslint-disable-next-line max-params -- mirrors the context-hash layout
function contextHash(
  txType: number,
  account: string,
  mptIssuanceID: string,
  sequence: number,
  suffix: string,
): string {
  return sha512Half(
    uintHex(txType, UINT16_BYTES) +
      accountIdHex(account) +
      mptIssuanceID +
      uintHex(sequence, UINT32_BYTES) +
      suffix,
  )
}

/**
 * Context hash the confidential LoanBrokerSet Schnorr proof is bound to: the
 * ConfidentialMPTConvert layout with the LoanBrokerSet transaction type,
 * `SHA-512Half(TxType || Account || MPTokenIssuanceID || Sequence || Account || 0)`.
 *
 * @param account - The LoanBroker owner's classic address.
 * @param mptIssuanceID - The 24-byte hex issuance ID of the Vault's asset.
 * @param sequence - The transaction's `Sequence` (or `TicketSequence`).
 * @returns The 32-byte hex context hash.
 */
export function getLoanBrokerSetContextHash(
  account: string,
  mptIssuanceID: string,
  sequence: number,
): string {
  return contextHash(
    LOAN_BROKER_SET_TX_TYPE,
    account,
    mptIssuanceID,
    sequence,
    accountIdHex(account) + uintHex(0, UINT32_BYTES),
  )
}

/**
 * Context hash the LoanBrokerSettle proof is bound to: the
 * ConfidentialMPTConvertBack layout with the LoanBrokerSettle transaction type
 * and the LoanBroker pseudo-account,
 * `SHA-512Half(TxType || Pseudo || MPTokenIssuanceID || Sequence || Pseudo || Version)`.
 *
 * @param brokerPseudoAccount - The LoanBroker pseudo-account's classic address.
 * @param mptIssuanceID - The 24-byte hex issuance ID of the Vault's asset.
 * @param sequence - The submitting owner's `Sequence` (or `TicketSequence`).
 * @param lendingBalanceVersion - The Lending Balance's `ConfidentialBalanceVersion`.
 * @returns The 32-byte hex context hash.
 */
// eslint-disable-next-line max-params -- mirrors the context-hash layout
export function getLoanBrokerSettleContextHash(
  brokerPseudoAccount: string,
  mptIssuanceID: string,
  sequence: number,
  lendingBalanceVersion: number,
): string {
  return contextHash(
    LOAN_BROKER_SETTLE_TX_TYPE,
    brokerPseudoAccount,
    mptIssuanceID,
    sequence,
    accountIdHex(brokerPseudoAccount) +
      uintHex(lendingBalanceVersion, UINT32_BYTES),
  )
}

/**
 * Context hash the confidential LoanSet proof is bound to: the
 * ConfidentialMPTSend layout with the LoanSet transaction type, the LoanBroker
 * pseudo-account as sender and the Borrower as destination,
 * `SHA-512Half(TxType || Pseudo || MPTokenIssuanceID || Sequence || Borrower || Version)`.
 *
 * @param brokerPseudoAccount - The LoanBroker pseudo-account's classic address.
 * @param mptIssuanceID - The 24-byte hex issuance ID of the Vault's asset.
 * @param sequence - The submitter's `Sequence` (or `TicketSequence`).
 * @param borrower - The Borrower's classic address.
 * @param lendingBalanceVersion - The Lending Balance's `ConfidentialBalanceVersion`.
 * @returns The 32-byte hex context hash.
 */
// eslint-disable-next-line max-params -- mirrors the context-hash layout
export function getLoanSetContextHash(
  brokerPseudoAccount: string,
  mptIssuanceID: string,
  sequence: number,
  borrower: string,
  lendingBalanceVersion: number,
): string {
  return contextHash(
    LOAN_SET_TX_TYPE,
    brokerPseudoAccount,
    mptIssuanceID,
    sequence,
    accountIdHex(borrower) + uintHex(lendingBalanceVersion, UINT32_BYTES),
  )
}

/** Inputs for {@link getConfidentialLoanPayContextHash}. */
export interface ConfidentialLoanPayContext {
  /** The Borrower's classic address. */
  borrower: string
  /** The 24-byte hex issuance ID of the Vault's asset. */
  mptIssuanceID: string
  /** The Borrower's `Sequence` (or `TicketSequence`). */
  sequence: number
  /** The LoanBroker pseudo-account's classic address. */
  brokerPseudoAccount: string
  /** The Borrower's `ConfidentialBalanceVersion`. */
  borrowerVersion: number
  /** The 32-byte hex LoanID. */
  loanID: string
  /** The Loan's `ConfidentialLoanVersion`. */
  loanVersion: number
}

/**
 * Context hash the ConfidentialLoanPay proof is bound to: the
 * ConfidentialMPTSend layout with the ConfidentialLoanPay transaction type,
 * followed by the LoanID and the Loan's `ConfidentialLoanVersion`,
 * `SHA-512Half(TxType || Borrower || MPTokenIssuanceID || Sequence || Pseudo ||
 * Version || LoanID || LoanVersion)`.
 *
 * @param context - The values the hash binds.
 * @returns The 32-byte hex context hash.
 */
export function getConfidentialLoanPayContextHash(
  context: ConfidentialLoanPayContext,
): string {
  return contextHash(
    CONFIDENTIAL_LOAN_PAY_TX_TYPE,
    context.borrower,
    context.mptIssuanceID,
    context.sequence,
    accountIdHex(context.brokerPseudoAccount) +
      uintHex(context.borrowerVersion, UINT32_BYTES) +
      context.loanID.toUpperCase() +
      uintHex(context.loanVersion, UINT32_BYTES),
  )
}
