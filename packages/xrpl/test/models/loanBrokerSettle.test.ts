import { validateLoanBrokerSettle } from '../../src/models/transactions/loanBrokerSettle'
import { assertTxIsValid, assertTxValidationError } from '../testUtils'

const assertValid = (tx: any): void =>
  assertTxIsValid(tx, validateLoanBrokerSettle)

const assertInvalid = (tx: any, errorMessage: string): void =>
  assertTxValidationError(tx, validateLoanBrokerSettle, errorMessage)

describe('unit test LoanBrokerSettle', () => {
  let tx: any

  beforeEach(() => {
    tx = {
      TransactionType: 'LoanBrokerSettle',
      Account: 'rPGxCzMicNJRe1U1CD5QyNjXdLUtdgSa7B',
      LoanBrokerID:
        'E9A08C918E26407493CC4ADD381BA979CFEB7E440D0863B01FB31C231D167E42',
      Amount: {
        mpt_issuance_id: '000004C463C52827307480341125DA0577DEFC38405B0E3E',
        value: '1000',
      },
      HolderEncryptedAmount: 'AB'.repeat(66),
      IssuerEncryptedAmount: 'AB'.repeat(66),
      AuditorEncryptedAmount: 'AB'.repeat(66),
      BlindingFactor: 'CD'.repeat(32),
      BalanceCommitment: 'AB'.repeat(33),
      ZKProof: 'AB'.repeat(816),
    }
  })

  test('valid tx', () => {
    assertValid(tx)
  })

  test('shares the Draw checks', () => {
    tx.Amount.value = '0'
    assertInvalid(
      tx,
      'LoanBrokerSettle: Amount must be a positive integer MPT amount',
    )
    tx.Amount.value = '1000'
    tx.LoanBrokerID = 'INCORRECT_VALUE'
    assertInvalid(
      tx,
      'LoanBrokerSettle: LoanBrokerID must be 64 characters hexadecimal string',
    )
  })

  test('missing or malformed BalanceCommitment', () => {
    tx.BalanceCommitment = 'AB'.repeat(32)
    assertInvalid(tx, 'LoanBrokerSettle: invalid field BalanceCommitment')
    delete tx.BalanceCommitment
    assertInvalid(tx, 'LoanBrokerSettle: missing field BalanceCommitment')
  })

  test('ZKProof must be a ConvertBack proof', () => {
    tx.ZKProof = 'AB'.repeat(946)
    assertInvalid(tx, 'LoanBrokerSettle: invalid field ZKProof')
  })
})
