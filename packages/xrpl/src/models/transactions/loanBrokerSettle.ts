import { MPTAmount } from '../common'

import {
  BaseTransaction,
  isHexWithByteLength,
  validateRequiredField,
  CONFIDENTIAL_CONVERT_BACK_PROOF_BYTES,
  CONFIDENTIAL_EC_POINT_BYTES,
} from './common'
import { validateLendingBalanceTransfer } from './loanBrokerDraw'

/**
 * The LoanBrokerSettle transaction returns MPTs from a confidential
 * LoanBroker's Lending Balance to its Vault (ConfidentialLendingProtocol). It
 * works like a ConfidentialMPTConvertBack whose destination is the Vault: it
 * first repays the LoanBroker's DebtTotal, and any excess is yield to the Vault.
 *
 * @category Transaction Models
 */
export interface LoanBrokerSettle extends BaseTransaction {
  TransactionType: 'LoanBrokerSettle'

  /**
   * The confidential LoanBroker settling the funds.
   */
  LoanBrokerID: string

  /**
   * The amount to settle, in the Vault's asset.
   */
  Amount: MPTAmount

  /**
   * ElGamal ciphertext of the amount under the Broker Key (66 bytes).
   * Subtracted from the Lending Balance's spending balance.
   */
  HolderEncryptedAmount: string

  /**
   * ElGamal ciphertext of the amount under the issuer's key (66 bytes).
   */
  IssuerEncryptedAmount: string

  /**
   * ElGamal ciphertext of the amount under the MPT Auditor's key (66 bytes).
   */
  AuditorEncryptedAmount: string

  /**
   * The scalar blinding factor (32 bytes) shared across the ciphertexts.
   */
  BlindingFactor: string

  /**
   * A Pedersen commitment (33 bytes) to the Lending Balance's spending balance.
   */
  BalanceCommitment: string

  /**
   * The 816-byte ConvertBack proof for the Lending Balance.
   */
  ZKProof: string
}

/**
 * Verify the form and type of a LoanBrokerSettle at runtime.
 *
 * @param tx - LoanBrokerSettle Transaction.
 * @throws When LoanBrokerSettle is Malformed.
 */
export function validateLoanBrokerSettle(tx: Record<string, unknown>): void {
  validateLendingBalanceTransfer(tx)
  validateRequiredField(
    tx,
    'BalanceCommitment',
    isHexWithByteLength(CONFIDENTIAL_EC_POINT_BYTES),
  )
  validateRequiredField(
    tx,
    'ZKProof',
    isHexWithByteLength(CONFIDENTIAL_CONVERT_BACK_PROOF_BYTES),
  )
}
