import { validateLoanBrokerMergeInbox } from '../../src/models/transactions/loanBrokerMergeInbox'
import { assertTxIsValid, assertTxValidationError } from '../testUtils'

const assertValid = (tx: any): void =>
  assertTxIsValid(tx, validateLoanBrokerMergeInbox)

const assertInvalid = (tx: any, errorMessage: string): void =>
  assertTxValidationError(tx, validateLoanBrokerMergeInbox, errorMessage)

describe('unit test LoanBrokerMergeInbox', () => {
  let tx: any

  beforeEach(() => {
    tx = {
      TransactionType: 'LoanBrokerMergeInbox',
      Account: 'rPGxCzMicNJRe1U1CD5QyNjXdLUtdgSa7B',
      LoanBrokerID:
        'E9A08C918E26407493CC4ADD381BA979CFEB7E440D0863B01FB31C231D167E42',
    }
  })

  test('valid tx', () => {
    assertValid(tx)
  })

  test('incorrect LoanBrokerID', () => {
    tx.LoanBrokerID = 'INCORRECT_VALUE'
    assertInvalid(
      tx,
      'LoanBrokerMergeInbox: LoanBrokerID must be 64 characters hexadecimal string',
    )

    delete tx.LoanBrokerID
    assertInvalid(tx, 'LoanBrokerMergeInbox: missing field LoanBrokerID')
  })
})
