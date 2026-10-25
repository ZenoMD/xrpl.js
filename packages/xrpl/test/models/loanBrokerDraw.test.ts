import { validateLoanBrokerDraw } from '../../src/models/transactions/loanBrokerDraw'
import { assertTxIsValid, assertTxValidationError } from '../testUtils'

const assertValid = (tx: any): void =>
  assertTxIsValid(tx, validateLoanBrokerDraw)

const assertInvalid = (tx: any, errorMessage: string): void =>
  assertTxValidationError(tx, validateLoanBrokerDraw, errorMessage)

const CIPHERTEXT = 'AB'.repeat(66)

describe('unit test LoanBrokerDraw', () => {
  let tx: any

  beforeEach(() => {
    tx = {
      TransactionType: 'LoanBrokerDraw',
      Account: 'rPGxCzMicNJRe1U1CD5QyNjXdLUtdgSa7B',
      LoanBrokerID:
        'E9A08C918E26407493CC4ADD381BA979CFEB7E440D0863B01FB31C231D167E42',
      Amount: {
        mpt_issuance_id: '000004C463C52827307480341125DA0577DEFC38405B0E3E',
        value: '1000',
      },
      HolderEncryptedAmount: CIPHERTEXT,
      IssuerEncryptedAmount: CIPHERTEXT,
      AuditorEncryptedAmount: CIPHERTEXT,
      BlindingFactor: 'CD'.repeat(32),
    }
  })

  test('valid tx', () => {
    assertValid(tx)
  })

  test('incorrect LoanBrokerID', () => {
    tx.LoanBrokerID = 'INCORRECT_VALUE'
    assertInvalid(
      tx,
      'LoanBrokerDraw: LoanBrokerID must be 64 characters hexadecimal string',
    )

    delete tx.LoanBrokerID
    assertInvalid(tx, 'LoanBrokerDraw: missing field LoanBrokerID')
  })

  test('non-MPT Amount', () => {
    tx.Amount = '1000'
    assertInvalid(tx, 'LoanBrokerDraw: invalid field Amount')
  })

  test('non-positive or non-integer Amount', () => {
    for (const value of ['0', '-1', '1.5', '9223372036854775808']) {
      tx.Amount.value = value
      assertInvalid(
        tx,
        'LoanBrokerDraw: Amount must be a positive integer MPT amount',
      )
    }
  })

  test('missing or malformed ciphertexts', () => {
    for (const field of [
      'HolderEncryptedAmount',
      'IssuerEncryptedAmount',
      'AuditorEncryptedAmount',
    ]) {
      const original = tx[field]
      tx[field] = 'AB'.repeat(65)
      assertInvalid(tx, `LoanBrokerDraw: invalid field ${field}`)
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete -- Necessary to delete key
      delete tx[field]
      assertInvalid(tx, `LoanBrokerDraw: missing field ${field}`)
      tx[field] = original
    }
  })

  test('malformed BlindingFactor', () => {
    tx.BlindingFactor = 'CD'.repeat(31)
    assertInvalid(tx, 'LoanBrokerDraw: invalid field BlindingFactor')
  })
})
