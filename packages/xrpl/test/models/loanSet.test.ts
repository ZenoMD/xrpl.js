import {
  LoanSetFlags,
  validateLoanSet,
} from '../../src/models/transactions/loanSet'
import { assertTxIsValid, assertTxValidationError } from '../testUtils'

const assertValid = (tx: any): void => assertTxIsValid(tx, validateLoanSet)

const assertInvalid = (tx: any, errorMessage: string): void =>
  assertTxValidationError(tx, validateLoanSet, errorMessage)

/**
 * A 66-byte ciphertext with the given C1 byte, so a term's ciphertexts can
 * share (or not share) their randomness.
 *
 * @param c1 - The repeated byte of C1.
 * @param c2 - The repeated byte of C2.
 * @returns The hex ciphertext.
 */
const ciphertext = (c1: string, c2: string): string =>
  `02${c1.repeat(32)}03${c2.repeat(32)}`

const POINT = `02${'AB'.repeat(32)}`

describe('unit test LoanSet', () => {
  let tx: any

  beforeEach(() => {
    tx = {
      TransactionType: 'LoanSet',
      Account: 'rPGxCzMicNJRe1U1CD5QyNjXdLUtdgSa7B',
      LoanBrokerID:
        'E9A08C918E26407493CC4ADD381BA979CFEB7E440D0863B01FB31C231D167E42',
      PrincipalRequested: '100000',
    }
  })

  test('valid public tx', () => {
    assertValid(tx)
  })

  test('PrincipalRequested is required for a public Loan', () => {
    delete tx.PrincipalRequested
    assertInvalid(tx, 'LoanSet: missing field PrincipalRequested')
  })

  describe('confidential', () => {
    beforeEach(() => {
      delete tx.PrincipalRequested
      Object.assign(tx, {
        Counterparty: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
        PaymentTotal: 12,
        SenderEncryptedAmount: ciphertext('11', '01'),
        DestinationEncryptedAmount: ciphertext('11', '02'),
        IssuerEncryptedAmount: ciphertext('11', '03'),
        AuditorEncryptedAmount: ciphertext('11', '04'),
        LoanAuditorEncryptedPrincipal: ciphertext('11', '05'),
        BorrowerEncryptedAmountOwed: ciphertext('22', '01'),
        BrokerEncryptedAmountOwed: ciphertext('22', '02'),
        LoanAuditorEncryptedAmountOwed: ciphertext('22', '03'),
        BorrowerEncryptedPeriodicPayment: ciphertext('33', '01'),
        BrokerEncryptedPeriodicPayment: ciphertext('33', '02'),
        LoanAuditorEncryptedPeriodicPayment: ciphertext('33', '03'),
        LoanAuditorEncryptionKey: POINT,
        BalanceCommitment: POINT,
        AmountCommitment: POINT,
        AmountOwedCommitment: POINT,
        PeriodicPaymentCommitment: POINT,
        ZKProof: 'AB'.repeat(3030),
      })
    })

    test('valid confidential tx', () => {
      assertValid(tx)
    })

    test('all confidential fields are required together', () => {
      delete tx.PeriodicPaymentCommitment
      assertInvalid(tx, 'LoanSet: missing field PeriodicPaymentCommitment')
    })

    test('malformed ciphertext, point or proof', () => {
      tx.BrokerEncryptedAmountOwed = 'AB'.repeat(65)
      assertInvalid(tx, 'LoanSet: invalid field BrokerEncryptedAmountOwed')
      tx.BrokerEncryptedAmountOwed = ciphertext('22', '02')
      tx.LoanAuditorEncryptionKey = 'AB'.repeat(32)
      assertInvalid(tx, 'LoanSet: invalid field LoanAuditorEncryptionKey')
      tx.LoanAuditorEncryptionKey = POINT
      tx.ZKProof = 'AB'.repeat(946)
      assertInvalid(tx, 'LoanSet: invalid field ZKProof')
    })

    test('public terms are not allowed', () => {
      tx.PrincipalRequested = '100'
      assertInvalid(
        tx,
        'LoanSet: PrincipalRequested is not allowed on a confidential Loan',
      )
      delete tx.PrincipalRequested
      tx.InterestRate = 500
      assertInvalid(
        tx,
        'LoanSet: InterestRate is not allowed on a confidential Loan',
      )
      delete tx.InterestRate
      tx.Flags = LoanSetFlags.tfLoanOverpayment
      assertInvalid(
        tx,
        'LoanSet: tfLoanOverpayment is not allowed on a confidential Loan',
      )
    })

    test("a term's ciphertexts must share one randomness", () => {
      tx.BrokerEncryptedAmountOwed = ciphertext('44', '02')
      assertInvalid(
        tx,
        'LoanSet: BorrowerEncryptedAmountOwed, BrokerEncryptedAmountOwed, LoanAuditorEncryptedAmountOwed must share one randomness',
      )
    })

    test('different terms must not share randomness', () => {
      tx.BorrowerEncryptedPeriodicPayment = ciphertext('22', '01')
      tx.BrokerEncryptedPeriodicPayment = ciphertext('22', '02')
      tx.LoanAuditorEncryptedPeriodicPayment = ciphertext('22', '03')
      assertInvalid(
        tx,
        'LoanSet: each confidential term must use a different randomness',
      )
    })
  })
})
