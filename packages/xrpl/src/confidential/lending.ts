/* eslint-disable max-lines -- the confidential LoanBroker builders share their ledger reads */
import { type Client } from '../client'
import { XrplError } from '../errors'
import { LedgerIndex } from '../models/common'
import {
  LoanBroker,
  LoanBrokerFlags,
  MPToken,
  MPTokenIssuance,
  Vault,
} from '../models/ledger'
import {
  LoanBrokerDraw,
  LoanBrokerMergeInbox,
  LoanBrokerSet,
  LoanBrokerSetFlags,
  LoanBrokerSettle,
} from '../models/transactions'
import { isFlagEnabled } from '../models/utils'

import {
  assertConfidentialAmount,
  decryptBound,
  fetchMPToken,
  fetchMPTokenIssuance,
  requireIssuerKey,
  resolveLedgerIndex,
  resolveSequence,
  resolveSpendingState,
} from './ledger'
import {
  getLoanBrokerSetContextHash,
  getLoanBrokerSettleContextHash,
} from './lendingContext'
import { loadMptCrypto } from './loader'
import {
  ConfidentialKeypair,
  ConfidentialLoanBrokerSetParams,
  LendingBalance,
  LoanBrokerDrawParams,
  LoanBrokerMergeInboxParams,
  LoanBrokerSettleParams,
} from './types'

/**
 * Fetch a ledger entry by its ID.
 *
 * @param client - A connected Client.
 * @param index - The 32-byte hex ledger entry ID.
 * @param ledgerIndex - Ledger to read at.
 * @returns The ledger entry.
 */
export async function fetchEntry<T>(
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
export async function fetchVaultIssuanceID(
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
  const [lending, sequence] = await Promise.all([
    fetchLendingContext(client, params.loanBrokerID, ledgerIndex),
    resolveSequence(client, params.account, params.sequence),
  ])
  const { mptIssuanceID, issuerKey, auditorKey, brokerKey } = lending

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
 * Build a LoanBrokerSettle transaction that returns a public amount from a
 * confidential LoanBroker's Lending Balance to its Vault. It is a
 * ConfidentialMPTConvertBack of the Lending Balance: the spending balance is
 * decrypted with the Broker Key to form the balance witness, and the proof binds
 * the LoanBrokerSettle context hash.
 *
 * @param client - A connected Client.
 * @param params - The settle inputs.
 * @returns The assembled, unsigned LoanBrokerSettle transaction.
 * @throws {XrplError} If the LoanBroker is not confidential, `brokerKeypair` is
 * not its Broker Key, or the amount exceeds the spendable Lending Balance.
 */
// eslint-disable-next-line max-lines-per-function -- one cohesive proof-assembly flow
export async function prepareLoanBrokerSettle(
  client: Client,
  params: LoanBrokerSettleParams,
): Promise<LoanBrokerSettle> {
  // rippled rejects a zero-amount settle with temBAD_AMOUNT.
  assertConfidentialAmount(params.amount, false)
  const [crypto, ledgerIndex] = await Promise.all([
    loadMptCrypto(),
    resolveLedgerIndex(client, params.ledgerIndex),
  ])
  const [lending, sequence] = await Promise.all([
    fetchLendingContext(client, params.loanBrokerID, ledgerIndex),
    resolveSequence(client, params.account, params.sequence),
  ])
  const { amount, brokerKeypair } = params
  requireBrokerKeypair(lending, brokerKeypair)
  const { spending, version } = resolveSpendingState(
    lending.lendingBalance,
    lending.broker.Account,
  )

  const [balance, blindingFactor, rho] = await Promise.all([
    crypto.decryptAmount(
      spending,
      brokerKeypair.privateKey,
      decryptBound(lending.issuance),
    ),
    crypto.generateBlindingFactor(),
    crypto.generateBlindingFactor(),
  ])
  if (amount > balance) {
    throw new XrplError(
      `Settle amount ${amount.toString()} exceeds the spendable Lending Balance ${balance.toString()}`,
    )
  }
  const balanceCommitment = await crypto.getPedersenCommitment(balance, rho)
  const contextHash = getLoanBrokerSettleContextHash(
    lending.broker.Account,
    lending.mptIssuanceID,
    sequence,
    version,
  )
  const [
    holderEncryptedAmount,
    issuerEncryptedAmount,
    auditorEncryptedAmount,
    zkProof,
  ] = await Promise.all([
    crypto.encryptAmount(amount, lending.brokerKey, blindingFactor),
    crypto.encryptAmount(amount, lending.issuerKey, blindingFactor),
    crypto.encryptAmount(amount, lending.auditorKey, blindingFactor),
    crypto.getConvertBackProof(
      brokerKeypair.privateKey,
      brokerKeypair.publicKey,
      contextHash,
      amount,
      {
        commitment: balanceCommitment,
        amount: balance,
        ciphertext: spending,
        blindingFactor: rho,
      },
    ),
  ])

  return {
    TransactionType: 'LoanBrokerSettle',
    Account: params.account,
    Sequence: sequence,
    LoanBrokerID: params.loanBrokerID,
    Amount: {
      mpt_issuance_id: lending.mptIssuanceID,
      value: amount.toString(),
    },
    HolderEncryptedAmount: holderEncryptedAmount,
    IssuerEncryptedAmount: issuerEncryptedAmount,
    AuditorEncryptedAmount: auditorEncryptedAmount,
    BlindingFactor: blindingFactor,
    BalanceCommitment: balanceCommitment,
    ZKProof: zkProof,
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
  const [{ issuance, lendingBalance }, crypto] = await Promise.all([
    fetchLendingContext(client, loanBrokerID, ledgerIndex),
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
export function requireAuditorKey(
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

/**
 * The ledger state a confidential LoanBroker's transactions are built from.
 */
export interface LendingContext {
  /** The confidential LoanBroker. */
  broker: LoanBroker
  /** The issuance ID of the Vault's asset. */
  mptIssuanceID: string
  /** The Vault asset's MPTokenIssuance. */
  issuance: MPTokenIssuance
  /** The LoanBroker pseudo-account's MPToken, holding the Lending Balance. */
  lendingBalance: MPToken
  /** The issuer's encryption key. */
  issuerKey: string
  /** The MPT Auditor's encryption key. */
  auditorKey: string
  /** The Broker Key. */
  brokerKey: string
}

/**
 * Read a confidential LoanBroker, its Vault's issuance and its Lending Balance,
 * all at one ledger.
 *
 * @param client - A connected Client.
 * @param loanBrokerID - The confidential LoanBroker.
 * @param ledgerIndex - Ledger to read at.
 * @returns The LoanBroker's lending context.
 * @throws {XrplError} If the LoanBroker is not confidential, or a key is missing.
 */
export async function fetchLendingContext(
  client: Client,
  loanBrokerID: string,
  ledgerIndex?: LedgerIndex,
): Promise<LendingContext> {
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
  const [issuance, lendingBalance] = await Promise.all([
    fetchMPTokenIssuance(client, mptIssuanceID, ledgerIndex),
    fetchMPToken(client, broker.Account, mptIssuanceID, ledgerIndex),
  ])
  const brokerKey = lendingBalance.HolderEncryptionKey
  if (brokerKey == null) {
    throw new XrplError(
      `LoanBroker ${loanBrokerID} has no registered Broker Key`,
    )
  }
  return {
    broker,
    mptIssuanceID,
    issuance,
    lendingBalance,
    issuerKey: requireIssuerKey(issuance, mptIssuanceID),
    auditorKey: requireAuditorKey(issuance.AuditorEncryptionKey, mptIssuanceID),
    brokerKey,
  }
}

/**
 * Check that a keypair is the LoanBroker's registered Broker Key, so a proof
 * built with it can verify.
 *
 * @param lending - The LoanBroker's lending context.
 * @param brokerKeypair - The keypair to check.
 * @throws {XrplError} If the public key is not the Broker Key.
 */
export function requireBrokerKeypair(
  lending: LendingContext,
  brokerKeypair: ConfidentialKeypair,
): void {
  if (
    brokerKeypair.publicKey.toUpperCase() !== lending.brokerKey.toUpperCase()
  ) {
    throw new XrplError(
      `brokerKeypair is not the Broker Key of LoanBroker ${lending.broker.index}`,
    )
  }
}
