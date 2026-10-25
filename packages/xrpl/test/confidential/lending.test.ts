import {
  decryptAmount,
  encryptAmount,
  getConvertBackContextHash,
  getConvertContextHash,
  getSendContextHash,
  verifyConvertBackSigmaProof,
} from '@xrplf/mpt-crypto'
import { assert } from 'chai'
import { decode, encode } from 'ripple-binary-codec'

import { type Client, validate } from '../../src'
import {
  accountIdHex,
  getConfidentialLoanPayContextHash,
  getLendingBalance,
  getLoanBrokerSetContextHash,
  getLoanBrokerSettleContextHash,
  getLoanSetContextHash,
  prepareConfidentialLoanBrokerSet,
  prepareLoanBrokerDraw,
  prepareLoanBrokerMergeInbox,
  prepareLoanBrokerSettle,
} from '../../src/confidential'
import { XrplError } from '../../src/errors'
import { LoanBrokerFlags } from '../../src/models/ledger'
import { LoanBrokerSetFlags } from '../../src/models/transactions'
import sha512Half from '../../src/utils/hashes/sha512Half'

import { ADDR_A, ADDR_B, ISSUANCE_ID, KEY_A, KEY_B } from './helpers'

// KEY_A is the Broker Key; KEY_B is used for the issuer and the auditor.
const BROKER_KEY = KEY_A
const ISSUER_KEY = KEY_B
const OWNER = ADDR_A
const PSEUDO_ACCOUNT = ADDR_B
const VAULT_ID = 'AA'.repeat(32)
const LOAN_BROKER_ID = 'BB'.repeat(32)

interface Fixtures {
  vault?: Record<string, unknown>
  broker?: Record<string, unknown>
  issuance?: Record<string, unknown>
  lendingBalance?: Record<string, unknown>
}

interface StubRequest {
  command: string
  index?: string
  mpt_issuance?: string
  mptoken?: { account: string }
}

/**
 * A Client stub serving a confidential LoanBroker over an MPT Vault.
 *
 * @param fixtures - Overrides for the Vault, LoanBroker, issuance and the
 *   pseudo-account's MPToken.
 * @returns A Client whose `request`/`getLedgerIndex` return the fixtures.
 */
function lendingClient(fixtures: Fixtures = {}): Client {
  const nodes: Record<string, Record<string, unknown>> = {
    [VAULT_ID]: { Asset: { mpt_issuance_id: ISSUANCE_ID }, ...fixtures.vault },
    [LOAN_BROKER_ID]: {
      Flags: LoanBrokerFlags.lsfLoanBrokerConfidential,
      VaultID: VAULT_ID,
      Account: PSEUDO_ACCOUNT,
      Owner: OWNER,
      ...fixtures.broker,
    },
  }
  const request = async (req: StubRequest): Promise<unknown> => {
    if (req.command === 'account_info') {
      return { result: { account_data: { Sequence: 7 } } }
    }
    if (req.index != null) {
      return { result: { node: nodes[req.index] } }
    }
    if (req.mpt_issuance != null) {
      return {
        result: {
          node: {
            IssuerEncryptionKey: ISSUER_KEY.publicKey,
            AuditorEncryptionKey: ISSUER_KEY.publicKey,
            ConfidentialOutstandingAmount: '10000',
            ...fixtures.issuance,
          },
        },
      }
    }
    if (req.mptoken?.account === PSEUDO_ACCOUNT) {
      return {
        result: {
          node: {
            HolderEncryptionKey: BROKER_KEY.publicKey,
            ...fixtures.lendingBalance,
          },
        },
      }
    }
    throw new Error(`unexpected request: ${JSON.stringify(req)}`)
  }
  return { request, getLedgerIndex: async () => 100 } as unknown as Client
}

/**
 * Assert that a builder call rejects with an {@link XrplError} whose message
 * matches `pattern`.
 *
 * @param promise - The pending builder call.
 * @param pattern - The expected message pattern.
 */
async function expectXrplError(
  promise: Promise<unknown>,
  pattern: RegExp,
): Promise<void> {
  let error: unknown
  try {
    await promise
  } catch (err) {
    error = err
  }
  assert.instanceOf(error, XrplError)
  assert.match((error as Error).message, pattern)
}

/**
 * Assert that a transaction passes model validation and survives a binary codec
 * round trip unchanged.
 *
 * @param tx - The transaction to check.
 */
function assertEncodable(tx: Record<string, unknown>): void {
  validate(tx)
  assert.deepEqual(decode(encode(tx)), tx)
}

describe('confidential/lending', function () {
  describe('getLoanBrokerSetContextHash', function () {
    /**
     * The Convert context-hash layout with a chosen transaction type.
     *
     * @param txType - The 2-byte hex transaction type.
     * @param sequence - The 4-byte hex sequence.
     * @returns The context hash.
     */
    function convertLayout(txType: string, sequence: string): string {
      const account = accountIdHex(OWNER)
      return sha512Half(
        `${txType + account + ISSUANCE_ID + sequence + account}00000000`,
      )
    }

    it('uses the same layout as the WASM Convert context hash', async function () {
      // ttCONFIDENTIAL_MPT_CONVERT (85): pins the layout rippled mirrors.
      assert.strictEqual(
        convertLayout('0055', '0000012C'),
        await getConvertContextHash(accountIdHex(OWNER), ISSUANCE_ID, 300),
      )
    })

    it('binds the LoanBrokerSet transaction type', function () {
      // ttLOAN_BROKER_SET (74)
      assert.strictEqual(
        getLoanBrokerSetContextHash(OWNER, ISSUANCE_ID, 300),
        convertLayout('004A', '0000012C'),
      )
    })
  })

  describe('lending context hashes', function () {
    const account = accountIdHex(OWNER)
    const pseudo = accountIdHex(PSEUDO_ACCOUNT)

    /**
     * The XLS-96 context prefix `TxType || Account || Issuance || Sequence`
     * followed by `suffix`.
     *
     * @param txType - The 2-byte hex transaction type.
     * @param accountHex - The 20-byte hex account.
     * @param suffix - The hex remainder of the layout.
     * @returns The context hash.
     */
    function layout(
      txType: string,
      accountHex: string,
      suffix: string,
    ): string {
      return sha512Half(`${txType}${accountHex}${ISSUANCE_ID}0000012C${suffix}`)
    }

    it('LoanSet uses the WASM Send layout with ttLOAN_SET', async function () {
      // ttCONFIDENTIAL_MPT_SEND (88) pins the layout.
      assert.strictEqual(
        layout('0058', pseudo, `${account}00000003`),
        await getSendContextHash(pseudo, ISSUANCE_ID, 300, account, 3),
      )
      assert.strictEqual(
        getLoanSetContextHash(PSEUDO_ACCOUNT, ISSUANCE_ID, 300, OWNER, 3),
        layout('0050', pseudo, `${account}00000003`),
      )
    })

    it('LoanBrokerSettle uses the WASM ConvertBack layout with ttLOAN_BROKER_SETTLE', async function () {
      // ttCONFIDENTIAL_MPT_CONVERT_BACK (87) pins the layout.
      assert.strictEqual(
        layout('0057', pseudo, `${pseudo}00000004`),
        await getConvertBackContextHash(pseudo, ISSUANCE_ID, 300, 4),
      )
      assert.strictEqual(
        getLoanBrokerSettleContextHash(PSEUDO_ACCOUNT, ISSUANCE_ID, 300, 4),
        layout('0053', pseudo, `${pseudo}00000004`),
      )
    })

    it('ConfidentialLoanPay appends the LoanID and Loan version to the Send layout', function () {
      assert.strictEqual(
        getConfidentialLoanPayContextHash({
          borrower: OWNER,
          mptIssuanceID: ISSUANCE_ID,
          sequence: 300,
          brokerPseudoAccount: PSEUDO_ACCOUNT,
          borrowerVersion: 5,
          loanID: LOAN_BROKER_ID,
          loanVersion: 2,
        }),
        // ttCONFIDENTIAL_LOAN_PAY (99)
        layout('0063', account, `${pseudo}00000005${LOAN_BROKER_ID}00000002`),
      )
    })
  })

  describe('prepareConfidentialLoanBrokerSet', function () {
    it('assembles a confidential LoanBrokerSet with the Broker Key and its proof', async function () {
      const tx = await prepareConfidentialLoanBrokerSet(lendingClient(), {
        account: OWNER,
        vaultID: VAULT_ID,
        brokerKeypair: BROKER_KEY,
        debtMaximum: '5000',
      })
      assert.strictEqual(tx.TransactionType, 'LoanBrokerSet')
      assert.strictEqual(tx.Sequence, 7)
      assert.strictEqual(tx.Flags, LoanBrokerSetFlags.tfLoanBrokerConfidential)
      assert.strictEqual(tx.VaultID, VAULT_ID)
      assert.strictEqual(tx.DebtMaximum, '5000')
      assert.isUndefined(tx.LoanBrokerID)
      assert.strictEqual(tx.HolderEncryptionKey, BROKER_KEY.publicKey)
      assert.lengthOf(tx.ZKProof as string, 128)
      assertEncodable(tx as unknown as Record<string, unknown>)
    })

    it('rejects a Vault whose asset is not an MPT', async function () {
      const client = lendingClient({ vault: { Asset: { currency: 'XRP' } } })
      await expectXrplError(
        prepareConfidentialLoanBrokerSet(client, {
          account: OWNER,
          vaultID: VAULT_ID,
          brokerKeypair: BROKER_KEY,
        }),
        /does not hold an MPT asset/u,
      )
    })

    it('rejects an issuance without an auditor key', async function () {
      const client = lendingClient({
        issuance: { AuditorEncryptionKey: undefined },
      })
      await expectXrplError(
        prepareConfidentialLoanBrokerSet(client, {
          account: OWNER,
          vaultID: VAULT_ID,
          brokerKeypair: BROKER_KEY,
        }),
        /AuditorEncryptionKey/u,
      )
    })
  })

  describe('prepareLoanBrokerDraw', function () {
    it('encrypts the amount under the Broker, issuer and auditor keys', async function () {
      const tx = await prepareLoanBrokerDraw(lendingClient(), {
        account: OWNER,
        loanBrokerID: LOAN_BROKER_ID,
        amount: 1000n,
        sequence: 9,
      })
      assert.strictEqual(tx.TransactionType, 'LoanBrokerDraw')
      assert.strictEqual(tx.Sequence, 9)
      assert.deepEqual(tx.Amount, {
        mpt_issuance_id: ISSUANCE_ID,
        value: '1000',
      })
      assert.strictEqual(
        await decryptAmount(
          tx.HolderEncryptedAmount,
          BROKER_KEY.privateKey,
          10_000n,
        ),
        1000n,
      )
      assert.deepEqual(
        await Promise.all(
          [tx.IssuerEncryptedAmount, tx.AuditorEncryptedAmount].map(
            async (ciphertext) =>
              decryptAmount(ciphertext, ISSUER_KEY.privateKey, 10_000n),
          ),
        ),
        [1000n, 1000n],
      )
      // The ciphertexts share the blinding factor validators check them with.
      assert.strictEqual(
        tx.HolderEncryptedAmount,
        await encryptAmount(1000n, BROKER_KEY.publicKey, tx.BlindingFactor),
      )
      assertEncodable(tx as unknown as Record<string, unknown>)
    })

    it('rejects a zero amount', async function () {
      await expectXrplError(
        prepareLoanBrokerDraw(lendingClient(), {
          account: OWNER,
          loanBrokerID: LOAN_BROKER_ID,
          amount: 0n,
        }),
        /out of range/u,
      )
    })

    it('rejects a LoanBroker that is not confidential', async function () {
      const client = lendingClient({ broker: { Flags: 0 } })
      await expectXrplError(
        prepareLoanBrokerDraw(client, {
          account: OWNER,
          loanBrokerID: LOAN_BROKER_ID,
          amount: 1n,
        }),
        /is not confidential/u,
      )
    })

    it('rejects a LoanBroker without a Broker Key', async function () {
      const client = lendingClient({
        lendingBalance: { HolderEncryptionKey: undefined },
      })
      await expectXrplError(
        prepareLoanBrokerDraw(client, {
          account: OWNER,
          loanBrokerID: LOAN_BROKER_ID,
          amount: 1n,
        }),
        /no registered Broker Key/u,
      )
    })
  })

  describe('prepareLoanBrokerSettle', function () {
    /**
     * A client whose Lending Balance spends `balance` at version 4.
     *
     * @param balance - The spendable Lending Balance.
     * @returns The client and the spending ciphertext.
     */
    async function settleClient(
      balance: bigint,
    ): Promise<{ client: Client; spending: string }> {
      const spending = await encryptAmount(
        balance,
        BROKER_KEY.publicKey,
        'CD'.repeat(32),
      )
      return {
        client: lendingClient({
          lendingBalance: {
            HolderEncryptionKey: BROKER_KEY.publicKey,
            ConfidentialBalanceSpending: spending,
            ConfidentialBalanceVersion: 4,
          },
        }),
        spending,
      }
    }

    it('proves the settle against the Lending Balance', async function () {
      const { client, spending } = await settleClient(1000n)
      const tx = await prepareLoanBrokerSettle(client, {
        account: OWNER,
        loanBrokerID: LOAN_BROKER_ID,
        amount: 400n,
        brokerKeypair: BROKER_KEY,
      })
      assert.strictEqual(tx.TransactionType, 'LoanBrokerSettle')
      assert.strictEqual(tx.Sequence, 7)
      assert.deepEqual(tx.Amount, {
        mpt_issuance_id: ISSUANCE_ID,
        value: '400',
      })
      assert.lengthOf(tx.ZKProof, 816 * 2)
      assertEncodable(tx as unknown as Record<string, unknown>)
      assert.strictEqual(
        tx.HolderEncryptedAmount,
        await encryptAmount(400n, BROKER_KEY.publicKey, tx.BlindingFactor),
      )
      // The ConvertBack sigma part proves ownership of the Lending Balance,
      // bound to the pseudo-account and the Lending Balance version.
      assert.isTrue(
        await verifyConvertBackSigmaProof(tx.ZKProof.slice(0, 256), {
          publicKey: BROKER_KEY.publicKey,
          ciphertext: spending,
          commitment: tx.BalanceCommitment,
          contextHash: getLoanBrokerSettleContextHash(
            PSEUDO_ACCOUNT,
            ISSUANCE_ID,
            7,
            4,
          ),
        }),
      )
    })

    it('rejects a settle above the spendable Lending Balance', async function () {
      const { client } = await settleClient(100n)
      await expectXrplError(
        prepareLoanBrokerSettle(client, {
          account: OWNER,
          loanBrokerID: LOAN_BROKER_ID,
          amount: 101n,
          brokerKeypair: BROKER_KEY,
        }),
        /exceeds the spendable Lending Balance 100/u,
      )
    })

    it('rejects a keypair that is not the Broker Key', async function () {
      const { client } = await settleClient(100n)
      await expectXrplError(
        prepareLoanBrokerSettle(client, {
          account: OWNER,
          loanBrokerID: LOAN_BROKER_ID,
          amount: 1n,
          brokerKeypair: KEY_B,
        }),
        /not the Broker Key/u,
      )
    })
  })

  describe('prepareLoanBrokerMergeInbox', function () {
    it('assembles a LoanBrokerMergeInbox with the account sequence', async function () {
      const tx = await prepareLoanBrokerMergeInbox(lendingClient(), {
        account: OWNER,
        loanBrokerID: LOAN_BROKER_ID,
      })
      assert.deepEqual(tx, {
        TransactionType: 'LoanBrokerMergeInbox',
        Account: OWNER,
        Sequence: 7,
        LoanBrokerID: LOAN_BROKER_ID,
      })
      assertEncodable(tx as unknown as Record<string, unknown>)
    })
  })

  describe('getLendingBalance', function () {
    it('decrypts the spending and inbox balances', async function () {
      const blindingFactor = 'CD'.repeat(32)
      const client = lendingClient({
        lendingBalance: {
          HolderEncryptionKey: BROKER_KEY.publicKey,
          ConfidentialBalanceSpending: await encryptAmount(
            700n,
            BROKER_KEY.publicKey,
            blindingFactor,
          ),
          ConfidentialBalanceInbox: await encryptAmount(
            300n,
            BROKER_KEY.publicKey,
            blindingFactor,
          ),
        },
      })
      assert.deepEqual(
        await getLendingBalance(client, LOAN_BROKER_ID, BROKER_KEY.privateKey),
        { spending: 700n, inbox: 300n },
      )
    })
  })
})
