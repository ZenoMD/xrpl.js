/* eslint-disable max-lines -- public and confidential LoanSet validation */
import { ValidationError } from '../../errors'
import { Signer } from '../common'
import { hasFlag } from '../utils'

import {
  BaseTransaction,
  CONFIDENTIAL_EC_POINT_BYTES,
  CONFIDENTIAL_ELGAMAL_CIPHERTEXT_BYTES,
  CONFIDENTIAL_LOAN_SET_PROOF_BYTES,
  isHexWithByteLength,
  validateHexMetadata,
  isLedgerEntryId,
  isNumber,
  isXRPLNumber,
  validateBaseTransaction,
  validateOptionalField,
  isString,
  validateRequiredField,
  XRPLNumber,
  GlobalFlagsInterface,
  Account,
  isAccount,
  isRecord,
} from './common'

const MAX_DATA_LENGTH = 512
const MAX_OVER_PAYMENT_FEE_RATE = 100_000
const MAX_INTEREST_RATE = 100_000
const MAX_LATE_INTEREST_RATE = 100_000
const MAX_CLOSE_INTEREST_RATE = 100_000
const MAX_OVER_PAYMENT_INTEREST_RATE = 100_000
const MIN_PAYMENT_INTERVAL = 60

/**
 * The transaction creates a new Loan object.
 *
 * @category Transaction Models
 */
export interface LoanSet extends BaseTransaction {
  TransactionType: 'LoanSet'

  /**
   * The Loan Broker ID associated with the loan.
   */
  LoanBrokerID: string

  /**
   * The principal amount requested by the Borrower. Required for a public Loan;
   * not allowed for a confidential one, whose principal is encrypted.
   */
  PrincipalRequested?: XRPLNumber

  /**
   * The signature of the counterparty over the transaction.
   */
  CounterpartySignature?: CounterpartySignature

  /**
   * The address of the counterparty of the Loan.
   */
  Counterparty?: Account

  /**
   * Arbitrary metadata in hex format. The field is limited to 512 characters.
   */
  Data?: string

  /**
   * A nominal funds amount paid to the LoanBroker.Owner when the Loan is created.
   */
  LoanOriginationFee?: XRPLNumber

  /**
   * A nominal amount paid to the LoanBroker.Owner with every Loan payment.
   */
  LoanServiceFee?: XRPLNumber

  /**
   * A nominal funds amount paid to the LoanBroker.Owner when a payment is late.
   */
  LatePaymentFee?: XRPLNumber

  /**
   * A nominal funds amount paid to the LoanBroker.Owner when an early full repayment is made.
   */
  ClosePaymentFee?: XRPLNumber

  /**
   * A fee charged on overpayments in 1/10th basis points. Valid values are between 0 and 100000 inclusive. (0 - 100%)
   */
  OverpaymentFee?: number

  /**
   * Annualized interest rate of the Loan in in 1/10th basis points. Valid values are between 0 and 100000 inclusive. (0 - 100%)
   */
  InterestRate?: number

  /**
   * A premium added to the interest rate for late payments in in 1/10th basis points.
   * Valid values are between 0 and 100000 inclusive. (0 - 100%)
   */
  LateInterestRate?: number

  /**
   * A Fee Rate charged for repaying the Loan early in 1/10th basis points.
   * Valid values are between 0 and 100000 inclusive. (0 - 100%)
   */
  CloseInterestRate?: number

  /**
   * An interest rate charged on over payments in 1/10th basis points. Valid values are between 0 and 100000 inclusive. (0 - 100%)
   */
  OverpaymentInterestRate?: number

  /**
   * The total number of payments to be made against the Loan.
   */
  PaymentTotal?: number

  /**
   * Number of seconds between Loan payments.
   */
  PaymentInterval?: number

  /**
   * The number of seconds after the Loan's Payment Due Date can be Defaulted.
   */
  GracePeriod?: number

  /*
   * Confidential Loan fields (ConfidentialLendingProtocol). Required together
   * for a Loan from a confidential LoanBroker, not allowed otherwise. Every
   * ciphertext is a 66-byte ElGamal ciphertext and every key or commitment a
   * 33-byte compressed point; the ciphertexts of each term (principal, Amount
   * Owed, Periodic Payment) share one randomness.
   */

  /** The principal under the Broker Key. Subtracted from the Lending Balance. */
  SenderEncryptedAmount?: string

  /** The principal under the Borrower's key. Credited to the Borrower's inbox. */
  DestinationEncryptedAmount?: string

  /** The principal under the issuer's key. */
  IssuerEncryptedAmount?: string

  /** The principal under the MPT Auditor's key. */
  AuditorEncryptedAmount?: string

  /** A commitment to the Lending Balance's spending balance. */
  BalanceCommitment?: string

  /** A commitment to the principal. */
  AmountCommitment?: string

  /** The 3030-byte confidential LoanSet proof, built by the Broker. */
  ZKProof?: string

  /** The Loan Auditor's ElGamal public key. */
  LoanAuditorEncryptionKey?: string

  /** The principal under the Loan Auditor's key. */
  LoanAuditorEncryptedPrincipal?: string

  /** The initial Amount Owed under the Borrower's key. */
  BorrowerEncryptedAmountOwed?: string

  /** The initial Amount Owed under the Broker Key. */
  BrokerEncryptedAmountOwed?: string

  /** The initial Amount Owed under the Loan Auditor's key. */
  LoanAuditorEncryptedAmountOwed?: string

  /** The Periodic Payment under the Borrower's key. */
  BorrowerEncryptedPeriodicPayment?: string

  /** The Periodic Payment under the Broker Key. */
  BrokerEncryptedPeriodicPayment?: string

  /** The Periodic Payment under the Loan Auditor's key. */
  LoanAuditorEncryptedPeriodicPayment?: string

  /** A commitment to the Amount Owed. */
  AmountOwedCommitment?: string

  /** A commitment to the Periodic Payment. */
  PeriodicPaymentCommitment?: string

  Flags?: number | LoanSetFlagsInterface
}

// Each term's ciphertexts, which share one randomness (and so their first 33
// bytes); different terms must not.
const CONFIDENTIAL_TERM_CIPHERTEXTS = [
  [
    'SenderEncryptedAmount',
    'DestinationEncryptedAmount',
    'IssuerEncryptedAmount',
    'AuditorEncryptedAmount',
    'LoanAuditorEncryptedPrincipal',
  ],
  [
    'BorrowerEncryptedAmountOwed',
    'BrokerEncryptedAmountOwed',
    'LoanAuditorEncryptedAmountOwed',
  ],
  [
    'BorrowerEncryptedPeriodicPayment',
    'BrokerEncryptedPeriodicPayment',
    'LoanAuditorEncryptedPeriodicPayment',
  ],
]

const CONFIDENTIAL_POINTS = [
  'LoanAuditorEncryptionKey',
  'BalanceCommitment',
  'AmountCommitment',
  'AmountOwedCommitment',
  'PeriodicPaymentCommitment',
]

const CONFIDENTIAL_FIELDS = [
  ...CONFIDENTIAL_TERM_CIPHERTEXTS.flat(),
  ...CONFIDENTIAL_POINTS,
  'ZKProof',
]

// Public terms a confidential LoanSet must not carry.
const PUBLIC_TERM_FIELDS = [
  'PrincipalRequested',
  'LoanOriginationFee',
  'LoanServiceFee',
  'LatePaymentFee',
  'ClosePaymentFee',
  'OverpaymentFee',
  'InterestRate',
  'LateInterestRate',
  'CloseInterestRate',
  'OverpaymentInterestRate',
]

/**
 * Whether a LoanSet creates a confidential Loan: it carries any of the
 * confidential fields.
 *
 * @param tx - LoanSet Transaction.
 * @returns True if any confidential field is present.
 */
export function isConfidentialLoanSet(tx: Record<string, unknown>): boolean {
  return CONFIDENTIAL_FIELDS.some((field) => tx[field] != null)
}

/**
 * An inner object that contains the signature of the Lender over the transaction.
 */
export interface CounterpartySignature {
  /**
   * The Public Key to be used to verify the validity of the signature.
   */
  SigningPubKey?: string

  /**
   * The signature of over all signing fields.
   */
  TxnSignature?: string

  /**
   * An array of transaction signatures from the Counterparty signers to indicate their approval of this transaction.
   */
  Signers?: Signer[]
}

/**
 * Transaction Flags for an LoanSet Transaction.
 *
 * @category Transaction Flags
 */
export enum LoanSetFlags {
  /**
   * Indicates that the loan supports over payments.
   */
  tfLoanOverpayment = 0x00010000,
}

/**
 * Map of flags to boolean values representing {@link LoanSet} transaction
 * flags.
 *
 * @category Transaction Flags
 */
export interface LoanSetFlagsInterface extends GlobalFlagsInterface {
  tfLoanOverpayment?: boolean
}

/**
 * Verify the form and type of an LoanSet at runtime.
 *
 * @param tx - LoanSet Transaction.
 * @throws When LoanSet is Malformed.
 */
// eslint-disable-next-line max-lines-per-function, max-statements -- due to many validations
export function validateLoanSet(tx: Record<string, unknown>): void {
  validateBaseTransaction(tx)

  validateRequiredField(tx, 'LoanBrokerID', isString)
  if (isConfidentialLoanSet(tx)) {
    validateConfidentialLoanSet(tx)
  } else {
    validateRequiredField(tx, 'PrincipalRequested', isXRPLNumber)
  }
  validateOptionalField(tx, 'CounterpartySignature', isRecord)
  validateOptionalField(tx, 'Data', isString)
  validateOptionalField(tx, 'Counterparty', isAccount)
  validateOptionalField(tx, 'LoanOriginationFee', isXRPLNumber)
  validateOptionalField(tx, 'LoanServiceFee', isXRPLNumber)
  validateOptionalField(tx, 'LatePaymentFee', isXRPLNumber)
  validateOptionalField(tx, 'ClosePaymentFee', isXRPLNumber)
  validateOptionalField(tx, 'OverpaymentFee', isNumber)
  validateOptionalField(tx, 'InterestRate', isNumber)
  validateOptionalField(tx, 'LateInterestRate', isNumber)
  validateOptionalField(tx, 'CloseInterestRate', isNumber)
  validateOptionalField(tx, 'OverpaymentInterestRate', isNumber)
  validateOptionalField(tx, 'PaymentTotal', isNumber)
  validateOptionalField(tx, 'PaymentInterval', isNumber)
  validateOptionalField(tx, 'GracePeriod', isNumber)

  if (!isLedgerEntryId(tx.LoanBrokerID)) {
    throw new ValidationError(
      `LoanSet: LoanBrokerID must be 64 characters hexadecimal string`,
    )
  }

  if (tx.Data != null && !validateHexMetadata(tx.Data, MAX_DATA_LENGTH)) {
    throw new ValidationError(
      `LoanSet: Data must be a valid non-empty hex string up to ${MAX_DATA_LENGTH} characters`,
    )
  }

  if (
    tx.OverpaymentFee != null &&
    (tx.OverpaymentFee < 0 || tx.OverpaymentFee > MAX_OVER_PAYMENT_FEE_RATE)
  ) {
    throw new ValidationError(
      `LoanSet: OverpaymentFee must be between 0 and ${MAX_OVER_PAYMENT_FEE_RATE} inclusive`,
    )
  }

  if (
    tx.InterestRate != null &&
    (tx.InterestRate < 0 || tx.InterestRate > MAX_INTEREST_RATE)
  ) {
    throw new ValidationError(
      `LoanSet: InterestRate must be between 0 and ${MAX_INTEREST_RATE} inclusive`,
    )
  }

  if (
    tx.LateInterestRate != null &&
    (tx.LateInterestRate < 0 || tx.LateInterestRate > MAX_LATE_INTEREST_RATE)
  ) {
    throw new ValidationError(
      `LoanSet: LateInterestRate must be between 0 and ${MAX_LATE_INTEREST_RATE} inclusive`,
    )
  }

  if (
    tx.CloseInterestRate != null &&
    (tx.CloseInterestRate < 0 || tx.CloseInterestRate > MAX_CLOSE_INTEREST_RATE)
  ) {
    throw new ValidationError(
      `LoanSet: CloseInterestRate must be between 0 and ${MAX_CLOSE_INTEREST_RATE} inclusive`,
    )
  }

  if (
    tx.OverpaymentInterestRate != null &&
    (tx.OverpaymentInterestRate < 0 ||
      tx.OverpaymentInterestRate > MAX_OVER_PAYMENT_INTEREST_RATE)
  ) {
    throw new ValidationError(
      `LoanSet: OverpaymentInterestRate must be between 0 and ${MAX_OVER_PAYMENT_INTEREST_RATE} inclusive`,
    )
  }

  if (tx.PaymentInterval != null && tx.PaymentInterval < MIN_PAYMENT_INTERVAL) {
    throw new ValidationError(
      `LoanSet: PaymentInterval must be greater than or equal to ${MIN_PAYMENT_INTERVAL}`,
    )
  }

  if (
    tx.PaymentInterval != null &&
    tx.GracePeriod != null &&
    tx.GracePeriod > tx.PaymentInterval
  ) {
    throw new ValidationError(
      `LoanSet: GracePeriod must not be greater than PaymentInterval`,
    )
  }
}

/**
 * Validate the fields of a confidential LoanSet, mirroring rippled's preflight.
 *
 * @param tx - LoanSet Transaction.
 * @throws When the confidential fields are malformed.
 */
// eslint-disable-next-line max-lines-per-function -- exhaustive validations
function validateConfidentialLoanSet(tx: Record<string, unknown>): void {
  for (const field of CONFIDENTIAL_TERM_CIPHERTEXTS.flat()) {
    validateRequiredField(
      tx,
      field,
      isHexWithByteLength(CONFIDENTIAL_ELGAMAL_CIPHERTEXT_BYTES),
    )
  }
  for (const field of CONFIDENTIAL_POINTS) {
    validateRequiredField(
      tx,
      field,
      isHexWithByteLength(CONFIDENTIAL_EC_POINT_BYTES),
    )
  }
  validateRequiredField(
    tx,
    'ZKProof',
    isHexWithByteLength(CONFIDENTIAL_LOAN_SET_PROOF_BYTES),
  )

  const publicTerm = PUBLIC_TERM_FIELDS.find((field) => tx[field] != null)
  if (publicTerm != null) {
    throw new ValidationError(
      `LoanSet: ${publicTerm} is not allowed on a confidential Loan`,
    )
  }
  if (hasFlag(tx, LoanSetFlags.tfLoanOverpayment, 'tfLoanOverpayment')) {
    throw new ValidationError(
      'LoanSet: tfLoanOverpayment is not allowed on a confidential Loan',
    )
  }

  const c1s = new Set<string>()
  for (const term of CONFIDENTIAL_TERM_CIPHERTEXTS) {
    const c1 = sharedC1(tx, term)
    if (c1 == null) {
      throw new ValidationError(
        `LoanSet: ${term.join(', ')} must share one randomness`,
      )
    }
    if (c1s.has(c1)) {
      throw new ValidationError(
        'LoanSet: each confidential term must use a different randomness',
      )
    }
    c1s.add(c1)
  }
}

/**
 * The first 33 bytes (C1 = r·G) shared by ciphertexts encrypted with one
 * randomness.
 *
 * @param tx - The transaction holding the ciphertexts.
 * @param fields - The ciphertext fields.
 * @returns The shared C1 as uppercase hex, or undefined if they differ.
 */
export function sharedC1(
  tx: Record<string, unknown>,
  fields: string[],
): string | undefined {
  const c1s = new Set(
    fields.map((field) =>
      String(tx[field])
        .slice(0, CONFIDENTIAL_EC_POINT_BYTES * 2)
        .toUpperCase(),
    ),
  )
  return c1s.size === 1 ? Array.from(c1s)[0] : undefined
}
