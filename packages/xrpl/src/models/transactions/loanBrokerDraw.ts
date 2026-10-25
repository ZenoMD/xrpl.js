import { ValidationError } from '../../errors'
import { MPTAmount } from '../common'

import {
  BaseTransaction,
  isHexWithByteLength,
  isLedgerEntryId,
  isMPTAmount,
  isString,
  validateBaseTransaction,
  validateRequiredField,
  CONFIDENTIAL_BLINDING_FACTOR_BYTES,
  CONFIDENTIAL_ELGAMAL_CIPHERTEXT_BYTES,
  MAX_MPT_AMOUNT,
} from './common'

/**
 * The LoanBrokerDraw transaction draws MPTs from a Vault into a confidential
 * LoanBroker's Lending Balance (ConfidentialLendingProtocol). The amount is
 * public; it is credited to the Lending Balance inbox as ciphertexts under the
 * Broker, issuer and auditor keys, which share one blinding factor so
 * validators can check them against the amount.
 *
 * @category Transaction Models
 */
export interface LoanBrokerDraw extends BaseTransaction {
  TransactionType: 'LoanBrokerDraw'

  /**
   * The confidential LoanBroker drawing the funds.
   */
  LoanBrokerID: string

  /**
   * The amount to draw, in the Vault's asset.
   */
  Amount: MPTAmount

  /**
   * ElGamal ciphertext of the amount under the Broker Key (66 bytes). Credited
   * to the Lending Balance inbox.
   */
  HolderEncryptedAmount: string

  /**
   * ElGamal ciphertext of the amount under the issuer's key (66 bytes).
   */
  IssuerEncryptedAmount: string

  /**
   * ElGamal ciphertext of the amount under the auditor's key (66 bytes).
   */
  AuditorEncryptedAmount: string

  /**
   * The scalar blinding factor (32 bytes) shared across the ciphertexts.
   */
  BlindingFactor: string
}

/**
 * Verify the form and type of a LoanBrokerDraw at runtime.
 *
 * @param tx - LoanBrokerDraw Transaction.
 * @throws When LoanBrokerDraw is Malformed.
 */
export function validateLoanBrokerDraw(tx: Record<string, unknown>): void {
  validateBaseTransaction(tx)

  validateRequiredField(tx, 'LoanBrokerID', isString)
  validateRequiredField(tx, 'Amount', isMPTAmount)
  for (const field of [
    'HolderEncryptedAmount',
    'IssuerEncryptedAmount',
    'AuditorEncryptedAmount',
  ]) {
    validateRequiredField(
      tx,
      field,
      isHexWithByteLength(CONFIDENTIAL_ELGAMAL_CIPHERTEXT_BYTES),
    )
  }
  validateRequiredField(
    tx,
    'BlindingFactor',
    isHexWithByteLength(CONFIDENTIAL_BLINDING_FACTOR_BYTES),
  )

  if (!isLedgerEntryId(tx.LoanBrokerID)) {
    throw new ValidationError(
      'LoanBrokerDraw: LoanBrokerID must be 64 characters hexadecimal string',
    )
  }

  const { value } = tx.Amount
  if (
    !/^\d+$/u.test(value) ||
    BigInt(value) === BigInt(0) ||
    BigInt(value) > MAX_MPT_AMOUNT
  ) {
    throw new ValidationError(
      'LoanBrokerDraw: Amount must be a positive integer MPT amount',
    )
  }
}
