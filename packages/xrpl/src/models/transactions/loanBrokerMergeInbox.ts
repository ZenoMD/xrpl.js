import { ValidationError } from '../../errors'

import {
  BaseTransaction,
  isLedgerEntryId,
  isString,
  validateBaseTransaction,
  validateRequiredField,
} from './common'

/**
 * The LoanBrokerMergeInbox transaction folds a confidential LoanBroker's
 * Lending Balance inbox into its spending balance (ConfidentialLendingProtocol).
 * The LoanBroker equivalent of ConfidentialMPTMergeInbox.
 *
 * @category Transaction Models
 */
export interface LoanBrokerMergeInbox extends BaseTransaction {
  TransactionType: 'LoanBrokerMergeInbox'

  /**
   * The confidential LoanBroker whose Lending Balance inbox is merged.
   */
  LoanBrokerID: string
}

/**
 * Verify the form and type of a LoanBrokerMergeInbox at runtime.
 *
 * @param tx - LoanBrokerMergeInbox Transaction.
 * @throws When LoanBrokerMergeInbox is Malformed.
 */
export function validateLoanBrokerMergeInbox(
  tx: Record<string, unknown>,
): void {
  validateBaseTransaction(tx)

  validateRequiredField(tx, 'LoanBrokerID', isString)

  if (!isLedgerEntryId(tx.LoanBrokerID)) {
    throw new ValidationError(
      'LoanBrokerMergeInbox: LoanBrokerID must be 64 characters hexadecimal string',
    )
  }
}
