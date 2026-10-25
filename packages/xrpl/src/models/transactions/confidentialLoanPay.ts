import { ValidationError } from '../../errors'
import { hasFlag } from '../utils'

import {
  BaseTransaction,
  GlobalFlagsInterface,
  isHexWithByteLength,
  isLedgerEntryId,
  isString,
  validateBaseTransaction,
  validateOptionalField,
  validateRequiredField,
  CONFIDENTIAL_EC_POINT_BYTES,
  CONFIDENTIAL_ELGAMAL_CIPHERTEXT_BYTES,
  CONFIDENTIAL_LOAN_FULL_PAY_PROOF_BYTES,
  CONFIDENTIAL_LOAN_PAY_PROOF_BYTES,
} from './common'
import { sharedC1 } from './loanSet'

/**
 * Enum representing values of {@link ConfidentialLoanPay} transaction flags.
 *
 * @category Transaction Flags
 */
export enum ConfidentialLoanPayFlags {
  /**
   * The payment is the whole Amount Owed and closes the Loan.
   */
  tfLoanFullPayment = 0x00020000,
}

/**
 * Map of flags to boolean values representing {@link ConfidentialLoanPay}
 * transaction flags.
 *
 * @category Transaction Flags
 */
// eslint-disable-next-line max-len -- prettier keeps the declaration on one line
export interface ConfidentialLoanPayFlagsInterface extends GlobalFlagsInterface {
  tfLoanFullPayment?: boolean
}

/**
 * The ConfidentialLoanPay transaction makes a payment on a confidential Loan
 * (ConfidentialLendingProtocol): a ConfidentialMPTSend of the payment from the
 * Borrower's confidential spending balance to the Lending Balance inbox. A
 * regular payment is at least the Periodic Payment and at most the Amount Owed;
 * a full payment (`tfLoanFullPayment`) is exactly the Amount Owed.
 *
 * @category Transaction Models
 */
export interface ConfidentialLoanPay extends BaseTransaction {
  TransactionType: 'ConfidentialLoanPay'

  /**
   * The confidential Loan being paid.
   */
  LoanID: string

  /**
   * The payment under the Borrower's key (66 bytes).
   */
  SenderEncryptedAmount: string

  /**
   * The payment under the Broker Key (66 bytes). Credited to the Lending
   * Balance inbox.
   */
  DestinationEncryptedAmount: string

  /**
   * The payment under the issuer's key (66 bytes).
   */
  IssuerEncryptedAmount: string

  /**
   * The payment under the MPT Auditor's key (66 bytes).
   */
  AuditorEncryptedAmount: string

  /**
   * The payment under the Loan Auditor's key (66 bytes).
   */
  LoanAuditorEncryptedAmount: string

  /**
   * A Pedersen commitment (33 bytes) to the Borrower's spending balance.
   */
  BalanceCommitment: string

  /**
   * A Pedersen commitment (33 bytes) to the payment.
   */
  AmountCommitment: string

  /**
   * A Pedersen commitment (33 bytes) to the Amount Owed. Required for a regular
   * payment, not allowed for a full payment.
   */
  AmountOwedCommitment?: string

  /**
   * A Pedersen commitment (33 bytes) to the Periodic Payment. Required for a
   * regular payment, not allowed for a full payment.
   */
  PeriodicPaymentCommitment?: string

  /**
   * The 2148-byte (regular) or 1202-byte (full) payment proof.
   */
  ZKProof: string

  Flags?: number | ConfidentialLoanPayFlagsInterface
}

// The payment's ciphertexts, which share one randomness.
const PAYMENT_CIPHERTEXTS = [
  'SenderEncryptedAmount',
  'DestinationEncryptedAmount',
  'IssuerEncryptedAmount',
  'AuditorEncryptedAmount',
  'LoanAuditorEncryptedAmount',
]

const SCHEDULE_COMMITMENTS = [
  'AmountOwedCommitment',
  'PeriodicPaymentCommitment',
]

/**
 * Verify the form and type of a ConfidentialLoanPay at runtime.
 *
 * @param tx - ConfidentialLoanPay Transaction.
 * @throws When ConfidentialLoanPay is Malformed.
 */
// eslint-disable-next-line max-lines-per-function -- exhaustive validations
export function validateConfidentialLoanPay(tx: Record<string, unknown>): void {
  validateBaseTransaction(tx)

  validateRequiredField(tx, 'LoanID', isString)
  for (const field of PAYMENT_CIPHERTEXTS) {
    validateRequiredField(
      tx,
      field,
      isHexWithByteLength(CONFIDENTIAL_ELGAMAL_CIPHERTEXT_BYTES),
    )
  }
  for (const field of ['BalanceCommitment', 'AmountCommitment']) {
    validateRequiredField(
      tx,
      field,
      isHexWithByteLength(CONFIDENTIAL_EC_POINT_BYTES),
    )
  }
  for (const field of SCHEDULE_COMMITMENTS) {
    validateOptionalField(
      tx,
      field,
      isHexWithByteLength(CONFIDENTIAL_EC_POINT_BYTES),
    )
  }

  if (!isLedgerEntryId(tx.LoanID)) {
    throw new ValidationError(
      'ConfidentialLoanPay: LoanID must be 64 characters hexadecimal string',
    )
  }

  const full = hasFlag(
    tx,
    ConfidentialLoanPayFlags.tfLoanFullPayment,
    'tfLoanFullPayment',
  )
  for (const field of SCHEDULE_COMMITMENTS) {
    if ((tx[field] != null) === full) {
      throw new ValidationError(
        `ConfidentialLoanPay: ${field} is ${
          full ? 'not allowed for a full' : 'required for a regular'
        } payment`,
      )
    }
  }
  validateRequiredField(
    tx,
    'ZKProof',
    isHexWithByteLength(
      full
        ? CONFIDENTIAL_LOAN_FULL_PAY_PROOF_BYTES
        : CONFIDENTIAL_LOAN_PAY_PROOF_BYTES,
    ),
  )

  if (sharedC1(tx, PAYMENT_CIPHERTEXTS) == null) {
    throw new ValidationError(
      'ConfidentialLoanPay: the payment ciphertexts must share one randomness',
    )
  }
}
