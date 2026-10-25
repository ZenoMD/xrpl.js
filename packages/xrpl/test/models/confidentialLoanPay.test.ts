import {
  ConfidentialLoanPayFlags,
  validateConfidentialLoanPay,
} from '../../src/models/transactions/confidentialLoanPay'
import { assertTxIsValid, assertTxValidationError } from '../testUtils'

const assertValid = (tx: any): void =>
  assertTxIsValid(tx, validateConfidentialLoanPay)

const assertInvalid = (tx: any, errorMessage: string): void =>
  assertTxValidationError(tx, validateConfidentialLoanPay, errorMessage)

const C1 = `02${'11'.repeat(32)}`
const POINT = `02${'AB'.repeat(32)}`

describe('unit test ConfidentialLoanPay', () => {
  let tx: any

  beforeEach(() => {
    tx = {
      TransactionType: 'ConfidentialLoanPay',
      Account: 'rPGxCzMicNJRe1U1CD5QyNjXdLUtdgSa7B',
      LoanID:
        'E9A08C918E26407493CC4ADD381BA979CFEB7E440D0863B01FB31C231D167E42',
      SenderEncryptedAmount: `${C1}03${'01'.repeat(32)}`,
      DestinationEncryptedAmount: `${C1}03${'02'.repeat(32)}`,
      IssuerEncryptedAmount: `${C1}03${'03'.repeat(32)}`,
      AuditorEncryptedAmount: `${C1}03${'04'.repeat(32)}`,
      LoanAuditorEncryptedAmount: `${C1}03${'05'.repeat(32)}`,
      BalanceCommitment: POINT,
      AmountCommitment: POINT,
      AmountOwedCommitment: POINT,
      PeriodicPaymentCommitment: POINT,
      ZKProof: 'AB'.repeat(2148),
    }
  })

  test('valid regular payment', () => {
    assertValid(tx)
  })

  test('valid full payment', () => {
    delete tx.AmountOwedCommitment
    delete tx.PeriodicPaymentCommitment
    tx.Flags = ConfidentialLoanPayFlags.tfLoanFullPayment
    tx.ZKProof = 'AB'.repeat(1202)
    assertValid(tx)
    tx.Flags = { tfLoanFullPayment: true }
    assertValid(tx)
  })

  test('incorrect LoanID', () => {
    tx.LoanID = 'INCORRECT_VALUE'
    assertInvalid(
      tx,
      'ConfidentialLoanPay: LoanID must be 64 characters hexadecimal string',
    )
  })

  test('schedule commitments are required for a regular payment', () => {
    delete tx.AmountOwedCommitment
    assertInvalid(
      tx,
      'ConfidentialLoanPay: AmountOwedCommitment is required for a regular payment',
    )
  })

  test('schedule commitments are not allowed for a full payment', () => {
    tx.Flags = ConfidentialLoanPayFlags.tfLoanFullPayment
    assertInvalid(
      tx,
      'ConfidentialLoanPay: AmountOwedCommitment is not allowed for a full payment',
    )
  })

  test('ZKProof length depends on the payment kind', () => {
    tx.ZKProof = 'AB'.repeat(1202)
    assertInvalid(tx, 'ConfidentialLoanPay: invalid field ZKProof')
  })

  test('the payment ciphertexts must share one randomness', () => {
    tx.LoanAuditorEncryptedAmount = `02${'22'.repeat(32)}03${'05'.repeat(32)}`
    assertInvalid(
      tx,
      'ConfidentialLoanPay: the payment ciphertexts must share one randomness',
    )
  })

  test('malformed ciphertext', () => {
    tx.IssuerEncryptedAmount = 'AB'.repeat(65)
    assertInvalid(
      tx,
      'ConfidentialLoanPay: invalid field IssuerEncryptedAmount',
    )
  })
})
