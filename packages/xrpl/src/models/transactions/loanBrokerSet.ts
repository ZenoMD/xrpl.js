import BigNumber from 'bignumber.js'

import { ValidationError } from '../../errors'
import { hasFlag } from '../utils'

import {
  BaseTransaction,
  GlobalFlagsInterface,
  isHexWithByteLength,
  CONFIDENTIAL_CONVERT_PROOF_BYTES,
  CONFIDENTIAL_EC_POINT_BYTES,
  validateHexMetadata,
  isLedgerEntryId,
  isNumber,
  isXRPLNumber,
  validateBaseTransaction,
  validateOptionalField,
  isString,
  validateRequiredField,
  XRPLNumber,
} from './common'

const MAX_DATA_LENGTH = 512
const MAX_MANAGEMENT_FEE_RATE = 10000
const MAX_COVER_RATE_MINIMUM = 100000
const MAX_COVER_RATE_LIQUIDATION = 100000

/**
 * Enum representing values of {@link LoanBrokerSet} transaction flags.
 *
 * @category Transaction Flags
 */
export enum LoanBrokerSetFlags {
  /**
   * Create the LoanBroker as confidential (ConfidentialLendingProtocol). Only
   * allowed when creating a LoanBroker; requires HolderEncryptionKey and ZKProof.
   */
  tfLoanBrokerConfidential = 0x00020000,
}

/**
 * Map of flags to boolean values representing {@link LoanBrokerSet} transaction
 * flags.
 *
 * @category Transaction Flags
 */
export interface LoanBrokerSetFlagsInterface extends GlobalFlagsInterface {
  tfLoanBrokerConfidential?: boolean
}

/**
 * The transaction creates a new LoanBroker object or updates an existing one.
 *
 * @category Transaction Models
 */
export interface LoanBrokerSet extends BaseTransaction {
  TransactionType: 'LoanBrokerSet'

  /**
   * The Vault ID that the Lending Protocol will use to access liquidity.
   */
  VaultID: string

  /**
   * The Loan Broker ID that the transaction is modifying.
   */
  LoanBrokerID?: string

  /**
   * Arbitrary metadata in hex format. The field is limited to 512 characters.
   */
  Data?: string

  /**
   * The 1/10th basis point fee charged by the Lending Protocol Owner. Valid values are between 0 and 10000 inclusive (1% - 10%).
   */
  ManagementFeeRate?: number

  /**
   * The maximum amount the protocol can owe the Vault.
   * The default value of 0 means there is no limit to the debt. Must not be negative.
   */
  DebtMaximum?: XRPLNumber

  /**
   * The 1/10th basis point DebtTotal that the first loss capital must cover. Valid values are between 0 and 100000 inclusive.
   */
  CoverRateMinimum?: number

  /**
   * The 1/10th basis point of minimum required first loss capital liquidated to cover a Loan default.
   * Valid values are between 0 and 100000 inclusive.
   */
  CoverRateLiquidation?: number

  /**
   * The Broker Key: the 33-byte compressed ElGamal public key the confidential
   * Lending Balance is encrypted under. Required with tfLoanBrokerConfidential,
   * otherwise not allowed.
   */
  HolderEncryptionKey?: string

  /**
   * A 64-byte Schnorr proof that the submitter knows the secret key for
   * HolderEncryptionKey. Required with tfLoanBrokerConfidential, otherwise not
   * allowed.
   */
  ZKProof?: string

  Flags?: number | LoanBrokerSetFlagsInterface
}

/**
 * Verify the form and type of an LoanBrokerSet at runtime.
 *
 * @param tx - LoanBrokerSet Transaction.
 * @throws When LoanBrokerSet is Malformed.
 */
// eslint-disable-next-line max-statements, max-lines-per-function -- due to exhaustive validations
export function validateLoanBrokerSet(tx: Record<string, unknown>): void {
  validateBaseTransaction(tx)

  validateRequiredField(tx, 'VaultID', isString)
  validateOptionalField(tx, 'LoanBrokerID', isString)
  validateOptionalField(tx, 'Data', isString)
  validateOptionalField(tx, 'ManagementFeeRate', isNumber)
  validateOptionalField(tx, 'DebtMaximum', isXRPLNumber)
  validateOptionalField(tx, 'CoverRateMinimum', isNumber)
  validateOptionalField(tx, 'CoverRateLiquidation', isNumber)

  if (!isLedgerEntryId(tx.VaultID)) {
    throw new ValidationError(
      `LoanBrokerSet: VaultID must be 64 characters hexadecimal string`,
    )
  }

  if (tx.LoanBrokerID != null && !isLedgerEntryId(tx.LoanBrokerID)) {
    throw new ValidationError(
      `LoanBrokerSet: LoanBrokerID must be 64 characters hexadecimal string`,
    )
  }

  if (tx.Data != null && !validateHexMetadata(tx.Data, MAX_DATA_LENGTH)) {
    throw new ValidationError(
      `LoanBrokerSet: Data must be a valid non-empty hex string up to ${MAX_DATA_LENGTH} characters`,
    )
  }

  if (
    tx.ManagementFeeRate != null &&
    (tx.ManagementFeeRate < 0 || tx.ManagementFeeRate > MAX_MANAGEMENT_FEE_RATE)
  ) {
    throw new ValidationError(
      `LoanBrokerSet: ManagementFeeRate must be between 0 and ${MAX_MANAGEMENT_FEE_RATE} inclusive`,
    )
  }

  if (tx.DebtMaximum != null && new BigNumber(tx.DebtMaximum).isLessThan(0)) {
    throw new ValidationError(
      'LoanBrokerSet: DebtMaximum must be a non-negative value',
    )
  }

  if (
    tx.CoverRateMinimum != null &&
    (tx.CoverRateMinimum < 0 || tx.CoverRateMinimum > MAX_COVER_RATE_MINIMUM)
  ) {
    throw new ValidationError(
      `LoanBrokerSet: CoverRateMinimum must be between 0 and ${MAX_COVER_RATE_MINIMUM} inclusive`,
    )
  }

  if (
    tx.CoverRateLiquidation != null &&
    (tx.CoverRateLiquidation < 0 ||
      tx.CoverRateLiquidation > MAX_COVER_RATE_LIQUIDATION)
  ) {
    throw new ValidationError(
      `LoanBrokerSet: CoverRateLiquidation must be between 0 and ${MAX_COVER_RATE_LIQUIDATION} inclusive`,
    )
  }

  // Validate that either both CoverRateMinimum and CoverRateLiquidation are zero,
  // or both are non-zero.
  const coverRateMinimumValue = tx.CoverRateMinimum ?? 0
  const coverRateLiquidationValue = tx.CoverRateLiquidation ?? 0

  if (
    (coverRateMinimumValue === 0 && coverRateLiquidationValue !== 0) ||
    (coverRateMinimumValue !== 0 && coverRateLiquidationValue === 0)
  ) {
    throw new ValidationError(
      'LoanBrokerSet: CoverRateMinimum and CoverRateLiquidation must both be zero or both be non-zero',
    )
  }

  validateConfidentialFields(tx)
}

/**
 * Validate the ConfidentialLendingProtocol fields of a LoanBrokerSet, mirroring
 * rippled's preflight: a confidential LoanBroker is only created (never
 * updated), carries both the Broker Key and its proof, and has no management
 * fee or First-Loss Capital.
 *
 * @param tx - LoanBrokerSet Transaction.
 * @throws When the confidential fields are malformed.
 */
// eslint-disable-next-line max-lines-per-function -- exhaustive validations
function validateConfidentialFields(tx: Record<string, unknown>): void {
  validateOptionalField(
    tx,
    'HolderEncryptionKey',
    isHexWithByteLength(CONFIDENTIAL_EC_POINT_BYTES),
  )
  validateOptionalField(
    tx,
    'ZKProof',
    isHexWithByteLength(CONFIDENTIAL_CONVERT_PROOF_BYTES),
  )

  const confidential = hasFlag(
    tx,
    LoanBrokerSetFlags.tfLoanBrokerConfidential,
    'tfLoanBrokerConfidential',
  )
  if (!confidential) {
    if (tx.HolderEncryptionKey != null || tx.ZKProof != null) {
      throw new ValidationError(
        'LoanBrokerSet: HolderEncryptionKey and ZKProof require tfLoanBrokerConfidential',
      )
    }
    return
  }

  if (tx.LoanBrokerID != null) {
    throw new ValidationError(
      'LoanBrokerSet: tfLoanBrokerConfidential can only be set when creating a LoanBroker',
    )
  }
  if (tx.HolderEncryptionKey == null || tx.ZKProof == null) {
    throw new ValidationError(
      'LoanBrokerSet: tfLoanBrokerConfidential requires HolderEncryptionKey and ZKProof',
    )
  }
  if (
    (tx.ManagementFeeRate ?? 0) !== 0 ||
    (tx.CoverRateMinimum ?? 0) !== 0 ||
    (tx.CoverRateLiquidation ?? 0) !== 0
  ) {
    throw new ValidationError(
      'LoanBrokerSet: a confidential LoanBroker must have zero ManagementFeeRate, CoverRateMinimum and CoverRateLiquidation',
    )
  }
}
