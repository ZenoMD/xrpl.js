import { type Client } from '../client'
import { XrplError } from '../errors'
import { LedgerIndex } from '../models/common'
import { LoanBroker, LoanBrokerFlags, Vault } from '../models/ledger'
import {
  LoanBrokerDraw,
  LoanBrokerMergeInbox,
  LoanBrokerSet,
  LoanBrokerSetFlags,
} from '../models/transactions'
import { isFlagEnabled } from '../models/utils'
import sha512Half from '../utils/hashes/sha512Half'

import {
  accountIdHex,
  assertConfidentialAmount,
  decryptBound,
  fetchMPToken,
  fetchMPTokenIssuance,
  requireIssuerKey,
  resolveLedgerIndex,
  resolveSequence,
} from './ledger'
import { loadMptCrypto } from './loader'
import {
  ConfidentialLoanBrokerSetParams,
  LendingBalance,
  LoanBrokerDrawParams,
  LoanBrokerMergeInboxParams,
} from './types'

// rippled ttLOAN_BROKER_SET, bound into the LoanBrokerSet context hash.
const LOAN_BROKER_SET_TX_TYPE = 74
const UINT16_BYTES = 2
const UINT32_BYTES = 4
const HEX_RADIX = 16

/**
 * Hex-encode an unsigned integer big-endian in `bytes` bytes.
 *
 * @param value - The integer to encode.
 * @param bytes - The encoded width.
 * @returns The uppercase hex encoding.
 */
function uintHex(value: number, bytes: number): string {
  return value
    .toString(HEX_RADIX)
    .toUpperCase()
    .padStart(bytes * 2, '0')
}

/**
 * Context hash the confidential LoanBrokerSet Schnorr proof is bound to. It has
 * the same layout as the ConfidentialMPTConvert context hash, but with the
 * LoanBrokerSet transaction type, which the mpt-crypto WASM hard-codes — so it is
 * computed here rather than there:
 * `SHA-512Half(TxType || Account || MPTokenIssuanceID || Sequence || Account || 0)`.
 *
 * @param account - The LoanBroker owner's classic address.
 * @param mptIssuanceID - The 24-byte hex issuance ID of the Vault's asset.
 * @param sequence - The transaction's `Sequence` (or `TicketSequence`).
 * @returns The 32-byte hex context hash.
 */
export function getLoanBrokerSetContextHash(
  account: string,
  mptIssuanceID: string,
  sequence: number,
): string {
  const accountHex = accountIdHex(account)
  return sha512Half(
    uintHex(LOAN_BROKER_SET_TX_TYPE, UINT16_BYTES) +
      accountHex +
      mptIssuanceID +
      uintHex(sequence, UINT32_BYTES) +
      accountHex +
      uintHex(0, UINT32_BYTES),
  )
}

/**
 * Fetch a ledger entry by its ID.
 *
 * @param client - A connected Client.
 * @param index - The 32-byte hex ledger entry ID.
 * @param ledgerIndex - Ledger to read at.
 * @returns The ledger entry.
 */
async function fetchEntry<T>(
  client: Client,
  index: string,
  ledgerIndex?: LedgerIndex,
): Promise<T> {
  const response = await client.request({
    command: 'ledger_entry',
    index,
    ledger_index: ledgerIndex,
  })
  // eslint-disable-next-line @typescript-eslint/consistent-type-assertions -- ledger_entry returns the requested entry type
  return response.result.node as unknown as T
}

/**
 * Read the MPTokenIssuanceID of a Vault's asset.
 *
 * @param client - A connected Client.
 * @param vaultID - The Vault ID.
 * @param ledgerIndex - Ledger to read at.
 * @returns The 24-byte hex issuance ID.
 * @throws {XrplError} If the Vault's asset is not an MPT.
 */
async function fetchVaultIssuanceID(
  client: Client,
  vaultID: string,
  ledgerIndex?: LedgerIndex,
): Promise<string> {
  const vault = await fetchEntry<Vault>(client, vaultID, ledgerIndex)
  if (!('mpt_issuance_id' in vault.Asset)) {
    throw new XrplError(`Vault ${vaultID} does not hold an MPT asset`)
  }
  return vault.Asset.mpt_issuance_id
}

/**
 * Fetch a LoanBroker, requiring that it is confidential.
 *
 * @param client - A connected Client.
 * @param loanBrokerID - The LoanBroker ID.
 * @param ledgerIndex - Ledger to read at.
 * @returns The LoanBroker ledger entry.
 * @throws {XrplError} If the LoanBroker is not confidential.
 */
export async function fetchConfidentialLoanBroker(
  client: Client,
  loanBrokerID: string,
  ledgerIndex?: LedgerIndex,
): Promise<LoanBroker> {
  const broker = await fetchEntry<LoanBroker>(client, loanBrokerID, ledgerIndex)
  if (!isFlagEnabled(broker.Flags, LoanBrokerFlags.lsfLoanBrokerConfidential)) {
    throw new XrplError(`LoanBroker ${loanBrokerID} is not confidential`)
  }
  return broker
}

/**
 * Build a LoanBrokerSet transaction that creates a confidential LoanBroker. It
 * registers the Broker Key, the key the LoanBroker's Lending Balance is
 * encrypted under, with a Schnorr proof that the submitter knows its secret key.
 *
 * @param client - A connected Client.
 * @param params - The LoanBroker inputs.
 * @returns The assembled, unsigned LoanBrokerSet transaction.
 * @throws {XrplError} If the Vault's asset is not an MPT or the issuance has no
 * issuer or auditor encryption key.
 */
// eslint-disable-next-line max-lines-per-function -- one cohesive proof-assembly flow
export async function prepareConfidentialLoanBrokerSet(
  client: Client,
  params: ConfidentialLoanBrokerSetParams,
): Promise<LoanBrokerSet> {
  const [crypto, ledgerIndex] = await Promise.all([
    loadMptCrypto(),
    resolveLedgerIndex(client, params.ledgerIndex),
  ])
  const [mptIssuanceID, sequence] = await Promise.all([
    fetchVaultIssuanceID(client, params.vaultID, ledgerIndex),
    resolveSequence(client, params.account, params.sequence),
  ])
  // Fail fast on an issuance rippled would reject (tecNO_PERMISSION).
  const issuance = await fetchMPTokenIssuance(
    client,
    mptIssuanceID,
    ledgerIndex,
  )
  requireIssuerKey(issuance, mptIssuanceID)
  requireAuditorKey(issuance.AuditorEncryptionKey, mptIssuanceID)

  const { brokerKeypair } = params
  const tx: LoanBrokerSet = {
    TransactionType: 'LoanBrokerSet',
    Account: params.account,
    Sequence: sequence,
    Flags: LoanBrokerSetFlags.tfLoanBrokerConfidential,
    VaultID: params.vaultID,
    HolderEncryptionKey: brokerKeypair.publicKey,
    ZKProof: await crypto.getConvertProof(
      brokerKeypair.publicKey,
      brokerKeypair.privateKey,
      getLoanBrokerSetContextHash(params.account, mptIssuanceID, sequence),
    ),
  }
  if (params.data != null) {
    tx.Data = params.data
  }
  if (params.debtMaximum != null) {
    tx.DebtMaximum = params.debtMaximum
  }
  return tx
}

/**
 * Build a LoanBrokerDraw transaction that draws MPTs from the Vault into a
 * confidential LoanBroker's Lending Balance inbox. The amount is encrypted under
 * the Broker Key (read from the LoanBroker pseudo-account's MPToken), the issuer
 * key and the auditor key with a shared blinding factor. Merge the inbox with
 * {@link prepareLoanBrokerMergeInbox} before lending the drawn funds.
 *
 * @param client - A connected Client.
 * @param params - The draw inputs.
 * @returns The assembled, unsigned LoanBrokerDraw transaction.
 * @throws {XrplError} If the LoanBroker is not confidential, or a key is missing.
 */
// eslint-disable-next-line max-lines-per-function -- one cohesive ciphertext-assembly flow
export async function prepareLoanBrokerDraw(
  client: Client,
  params: LoanBrokerDrawParams,
): Promise<LoanBrokerDraw> {
  // rippled rejects a zero-amount draw with temBAD_AMOUNT.
  assertConfidentialAmount(params.amount, false)
  const [crypto, ledgerIndex] = await Promise.all([
    loadMptCrypto(),
    resolveLedgerIndex(client, params.ledgerIndex),
  ])
  const [broker, sequence] = await Promise.all([
    fetchConfidentialLoanBroker(client, params.loanBrokerID, ledgerIndex),
    resolveSequence(client, params.account, params.sequence),
  ])
  const mptIssuanceID = await fetchVaultIssuanceID(
    client,
    broker.VaultID,
    ledgerIndex,
  )
  const [issuance, lendingBalance] = await Promise.all([
    fetchMPTokenIssuance(client, mptIssuanceID, ledgerIndex),
    fetchMPToken(client, broker.Account, mptIssuanceID, ledgerIndex),
  ])
  const issuerKey = requireIssuerKey(issuance, mptIssuanceID)
  const auditorKey = requireAuditorKey(
    issuance.AuditorEncryptionKey,
    mptIssuanceID,
  )
  const brokerKey = lendingBalance.HolderEncryptionKey
  if (brokerKey == null) {
    throw new XrplError(
      `LoanBroker ${params.loanBrokerID} has no registered Broker Key`,
    )
  }

  const { amount } = params
  const blindingFactor = await crypto.generateBlindingFactor()
  const [holderEncryptedAmount, issuerEncryptedAmount, auditorEncryptedAmount] =
    await Promise.all([
      crypto.encryptAmount(amount, brokerKey, blindingFactor),
      crypto.encryptAmount(amount, issuerKey, blindingFactor),
      crypto.encryptAmount(amount, auditorKey, blindingFactor),
    ])

  return {
    TransactionType: 'LoanBrokerDraw',
    Account: params.account,
    Sequence: sequence,
    LoanBrokerID: params.loanBrokerID,
    Amount: { mpt_issuance_id: mptIssuanceID, value: amount.toString() },
    HolderEncryptedAmount: holderEncryptedAmount,
    IssuerEncryptedAmount: issuerEncryptedAmount,
    AuditorEncryptedAmount: auditorEncryptedAmount,
    BlindingFactor: blindingFactor,
  }
}

/**
 * Build a LoanBrokerMergeInbox transaction that folds a confidential
 * LoanBroker's Lending Balance inbox into its spending balance. No crypto
 * material is required; the builder only resolves the account sequence.
 *
 * @param client - A connected Client.
 * @param params - The merge-inbox inputs.
 * @returns The assembled, unsigned LoanBrokerMergeInbox transaction.
 */
export async function prepareLoanBrokerMergeInbox(
  client: Client,
  params: LoanBrokerMergeInboxParams,
): Promise<LoanBrokerMergeInbox> {
  return {
    TransactionType: 'LoanBrokerMergeInbox',
    Account: params.account,
    Sequence: await resolveSequence(client, params.account, params.sequence),
    LoanBrokerID: params.loanBrokerID,
  }
}

/**
 * Decrypt a confidential LoanBroker's Lending Balance, held on the LoanBroker
 * pseudo-account's MPToken.
 *
 * @param client - A connected Client.
 * @param loanBrokerID - The confidential LoanBroker.
 * @param privateKey - The 32-byte hex private Broker Key.
 * @returns The decrypted spending and inbox balances.
 * @throws {XrplError} If the LoanBroker is not confidential.
 */
export async function getLendingBalance(
  client: Client,
  loanBrokerID: string,
  privateKey: string,
): Promise<LendingBalance> {
  // One ledger for every read, so the decrypt bound covers the balances.
  const ledgerIndex = await client.getLedgerIndex()
  const broker = await fetchConfidentialLoanBroker(
    client,
    loanBrokerID,
    ledgerIndex,
  )
  const mptIssuanceID = await fetchVaultIssuanceID(
    client,
    broker.VaultID,
    ledgerIndex,
  )
  const [issuance, lendingBalance, crypto] = await Promise.all([
    fetchMPTokenIssuance(client, mptIssuanceID, ledgerIndex),
    fetchMPToken(client, broker.Account, mptIssuanceID, ledgerIndex),
    loadMptCrypto(),
  ])
  const bound = decryptBound(issuance)
  async function decrypt(ciphertext?: string): Promise<bigint> {
    if (ciphertext == null) {
      return BigInt(0)
    }
    return crypto.decryptAmount(ciphertext, privateKey, bound)
  }
  const [spending, inbox] = await Promise.all([
    decrypt(lendingBalance.ConfidentialBalanceSpending),
    decrypt(lendingBalance.ConfidentialBalanceInbox),
  ])
  return { spending, inbox }
}

/**
 * Read the issuance's auditor encryption key, which confidential lending
 * requires.
 *
 * @param auditorKey - The issuance's `AuditorEncryptionKey`.
 * @param mptIssuanceID - The issuance ID, for the error message.
 * @returns The auditor's 33-byte hex public key.
 * @throws {XrplError} If no auditor encryption key is registered.
 */
function requireAuditorKey(
  auditorKey: string | undefined,
  mptIssuanceID: string,
): string {
  if (auditorKey == null) {
    throw new XrplError(
      `Issuance ${mptIssuanceID} has no registered AuditorEncryptionKey`,
    )
  }
  return auditorKey
}
