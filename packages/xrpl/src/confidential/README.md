# Confidential MPT

High-level builders for **Confidential MPT (XLS-0096)** — the flow that replaces
a public MPT balance with on-ledger EC-ElGamal ciphertexts and zero-knowledge
proofs, so amounts are hidden from everyone except the parties and (optionally) a
registered auditor.

Each builder queries the ledger state it needs, generates the ciphertexts,
commitments, and the ordered zero-knowledge proof, and returns an **unsigned**
transaction — so you never hand-build cryptographic material. The crypto itself
lives in the [`@xrplf/mpt-crypto`](../../../mpt-crypto) dependency, reached only
through a dynamic `import`, so its ~2 MB WASM loads lazily on the first confidential
transaction you assemble — an app that never assembles one never loads it.

These builders are exported from `xrpl`'s main entry point:

```ts
import {
  deriveConfidentialKeypair,
  prepareConfidentialConvert,
  prepareConfidentialSend,
  // ...
} from 'xrpl'
```

## Keys

A confidential balance is encrypted under an **ElGamal keypair** (a secp256k1
key: 32-byte hex private scalar, 33-byte hex compressed public key), **distinct
from the account's signing key**. Derive one with `deriveConfidentialKeypair()`:

```ts
// No argument: generates a fresh, dedicated secp256k1 key. Persist its
// `privateKey` — it is the only thing that can decrypt the balance.
const aliceKey = deriveConfidentialKeypair()
```

If you would rather back up a *seed* than a raw private key, generate a dedicated
seed yourself and re-derive from it — the keypair is deterministic in the seed:

```ts
import { generateSeed } from 'ripple-keypairs'

const seed = generateSeed({ algorithm: 'ecdsa-secp256k1' }) // store this
const aliceKey = deriveConfidentialKeypair(seed)
```

- **Persist the private key (or the seed).** It is the only thing that can
  decrypt the balance; lose it and the funds become undecryptable (though the
  issuer can still claw them back). It is never sent to the ledger.
- Use a **dedicated** key. Do **not** pass the account's signing seed: it derives
  the same scalar and extends that key's trust boundary to the confidential
  crypto. Both forms above are dedicated; reusing the signing seed is the case to
  avoid.

## Usage

Every builder returns an unsigned transaction with `Sequence` **pinned** — submit
it directly. `submitAndWait` autofills the fee and `LastLedgerSequence` but does
not overwrite an already-set `Sequence`, so the proof stays bound to the sequence
it was built for. Do not re-derive `Sequence` yourself.

```ts
import { Client } from 'xrpl'
import {
  deriveConfidentialKeypair,
  prepareConfidentialConvert,
  prepareConfidentialSend,
  prepareConfidentialMergeInbox,
  getConfidentialBalance,
} from 'xrpl'

const client = new Client('wss://...')
await client.connect()

// Assumes `alice` and `bob` are funded `Wallet`s and `mptIssuanceID` is an
// existing MPT issuance created with the confidential-balance flag enabled.

// ElGamal keypair — distinct from the signing key; persist the private key.
const aliceKey = deriveConfidentialKeypair()

// 1. Convert 1000 public MPT into alice's confidential balance.
const convert = await prepareConfidentialConvert(client, {
  account: alice.classicAddress,
  amount: 1000n,
  holderKeypair: aliceKey,
  mptIssuanceID,
})
await client.submitAndWait(convert, { wallet: alice })

// 2. Send 300 confidentially to bob (who must already have a registered key).
const send = await prepareConfidentialSend(client, {
  account: alice.classicAddress,
  destination: bob.classicAddress,
  amount: 300n,
  senderKeypair: aliceKey,
  mptIssuanceID,
})
await client.submitAndWait(send, { wallet: alice })

// 3. bob folds the amount received in its inbox into its spendable balance.
const merge = await prepareConfidentialMergeInbox(client, {
  account: bob.classicAddress,
  mptIssuanceID,
})
await client.submitAndWait(merge, { wallet: bob })

// Read a confidential balance back (needs the private key to decrypt).
const spendable = await getConfidentialBalance(
  client,
  alice.classicAddress,
  mptIssuanceID,
  aliceKey.privateKey,
) // 700n

// ConvertBack (reveal to public) and Clawback (issuer) follow the same
// prepare -> submitAndWait pattern.
```

## Builders

| Builder | Actor | Purpose |
| --- | --- | --- |
| `prepareConfidentialConvert` | holder | Move public MPT into the holder's confidential balance. Registers the holder's encryption key on the first conversion. |
| `prepareConfidentialSend` | holder | Transfer a confidential amount to another holder's inbox, encrypted under the sender, destination, issuer, and (if registered) auditor keys. |
| `prepareConfidentialMergeInbox` | holder | Fold pending inbox amounts into the spendable balance. Requires no crypto material. |
| `prepareConfidentialConvertBack` | holder | Reveal a confidential amount back to a public MPT balance. |
| `prepareConfidentialClawback` | issuer | Burn a holder's **entire** confidential balance (all-or-nothing). |

Parameter shapes for each are in [`types.ts`](./types.ts).

## Confidential lending

A confidential LoanBroker (Confidential Lending Protocol) lends from a
**Lending Balance**: a confidential balance on the LoanBroker pseudo-account's
MPToken, encrypted under the **Broker Key**. The Vault's asset must be an MPT
with confidential balances enabled and both an issuer and an auditor key.

```ts
import {
  deriveConfidentialKeypair,
  getLendingBalance,
  prepareConfidentialLoanBrokerSet,
  prepareLoanBrokerDraw,
  prepareLoanBrokerMergeInbox,
} from 'xrpl'

// The Broker Key — persist the private key, it decrypts the Lending Balance.
const brokerKey = deriveConfidentialKeypair()

// 1. Create the confidential LoanBroker over a Vault the broker owns.
const create = await prepareConfidentialLoanBrokerSet(client, {
  account: broker.classicAddress,
  vaultID,
  brokerKeypair: brokerKey,
})
await client.submitAndWait(create, { wallet: broker })
// The LoanBrokerID is the created LoanBroker entry's index, from the metadata.

// 2. Draw 1000 from the Vault into the Lending Balance inbox.
const draw = await prepareLoanBrokerDraw(client, {
  account: broker.classicAddress,
  loanBrokerID,
  amount: 1000n,
})
await client.submitAndWait(draw, { wallet: broker })

// 3. Merge the inbox into the spendable Lending Balance.
const merge = await prepareLoanBrokerMergeInbox(client, {
  account: broker.classicAddress,
  loanBrokerID,
})
await client.submitAndWait(merge, { wallet: broker })

await getLendingBalance(client, loanBrokerID, brokerKey.privateKey)
// { spending: 1000n, inbox: 0n }
```

| Builder | Actor | Purpose |
| --- | --- | --- |
| `prepareConfidentialLoanBrokerSet` | broker | Create a confidential LoanBroker, registering the Broker Key with a Schnorr proof bound to the `LoanBrokerSet` context hash. |
| `prepareLoanBrokerDraw` | broker | Draw a public amount from the Vault into the Lending Balance inbox, encrypted under the Broker, issuer and auditor keys. |
| `prepareLoanBrokerMergeInbox` | broker | Fold the Lending Balance inbox into its spendable balance. Requires no crypto material. |
| `prepareLoanBrokerSettle` | broker | Return a public amount from the spendable Lending Balance to the Vault (a ConvertBack of the Lending Balance). |
| `prepareConfidentialLoanSet` | broker | Create a confidential Loan: move the principal to the Borrower's inbox and encrypt the principal, Amount Owed and Periodic Payment under the Borrower, Broker and Loan Auditor keys, with the 3030-byte LoanSet proof. |
| `prepareConfidentialLoanPay` | borrower | Pay a confidential Loan from the Borrower's confidential balance into the Lending Balance inbox — a regular payment (Periodic Payment ≤ X ≤ Amount Owed) or a full payment that closes it. |

### Loans

The Broker builds a confidential LoanSet, since its proof spends from the Lending
Balance. Whichever party submits it, the other adds `CounterpartySignature` with
`signLoanSetByCounterparty`:

```ts
const loanSet = await prepareConfidentialLoanSet(client, {
  account: broker.classicAddress, // or the Borrower; the proof binds its sequence
  loanBrokerID,
  borrower: borrower.classicAddress, // must already hold a confidential balance
  brokerKeypair: brokerKey,
  loanAuditorKey: loanAuditor.publicKey,
  principal: 600n,
  amountOwed: 660n, // >= principal
  periodicPayment: 60n, // paymentTotal * periodicPayment >= amountOwed
  paymentTotal: 12,
  paymentInterval: 2_592_000,
})
// Autofill before the counterparty signs, so submitting changes no signed field.
const filled = await client.autofill(loanSet)
const { tx: cosigned } = signLoanSetByCounterparty(borrower, filled)
await client.submitAndWait(cosigned, { wallet: broker })

// The Borrower pays; a payment equal to the Amount Owed is a full payment.
const pay = await prepareConfidentialLoanPay(client, {
  account: borrower.classicAddress,
  loanID,
  amount: 60n,
  borrowerKeypair: borrowerKey,
  // The agreed terms, checked against the Loan in constant time; without them
  // the builder searches for them (~3s per million).
  amountOwed: 660n,
  periodicPayment: 60n,
})
await client.submitAndWait(pay, { wallet: borrower })
```

These are not yet supported as `prepareConfidentialBatch` operations.

## Batching

`prepareConfidentialBatch` (the assembler) builds a Batch (XLS-56) whose inner
transactions include Confidential MPT operations, mixed freely with plain
transactions. It exists because a confidential proof binds the transaction's
**`Sequence`** — and, for `send`/`convertBack`, the live
`ConfidentialBalanceSpending` + `ConfidentialBalanceVersion` — at build time.
Inside a Batch each inner's sequence is position-dependent, so the proof must be
built with the final value (`autofill` can't re-derive a proof afterward); and
when several balance-mutating operations for the same `(account, token)` share one
Batch, each proof must bind the balance the previous one leaves behind. The
assembler owns all of that.

Pass the outer Batch account and an ordered list of inners — each either a
confidential operation spec (the matching builder's params minus `sequence`, plus an
`operation` tag) or a pre-built plain transaction. Array order is on-ledger execution order.

```ts
import { prepareConfidentialBatch } from 'xrpl'

// Atomic multi-send: alice pays two recipients confidentially in one Batch.
const batch = await prepareConfidentialBatch(client, {
  account: alice.classicAddress,
  inners: [
    { operation: 'send', account: alice.classicAddress, destination: bob.classicAddress, amount: 100n, senderKeypair: aliceKey, mptIssuanceID },
    { operation: 'send', account: alice.classicAddress, destination: carol.classicAddress, amount: 50n, senderKeypair: aliceKey, mptIssuanceID },
  ],
})
const { tx_blob } = alice.sign(batch)
await client.submit(tx_blob)
```

Inners mix confidential operations with plain transactions freely: a confidential
operation spec is a *recipe* (`operation`-tagged, camelCase — it mirrors the builder's
params), while a
plain transaction is the normal wire model (`TransactionType`, PascalCase). The
assembler builds and proves the operation specs and shapes the plain ones as Batch inners:

```ts
const batch = await prepareConfidentialBatch(client, {
  account: alice.classicAddress,
  inners: [
    // a confidential operation spec — the assembler builds the tx + proof from it
    { operation: 'send', account: alice.classicAddress, destination: bob.classicAddress, amount: 100n, senderKeypair: aliceKey, mptIssuanceID },
    // a plain transaction — shaped as a Batch inner and passed through
    { TransactionType: 'Payment', Account: alice.classicAddress, Destination: carol.classicAddress, Amount: '1000000' },
  ],
})
const { tx_blob } = alice.sign(batch)
await client.submit(tx_blob)
```

Operation types are `send`, `convert`, `convertBack`, `mergeInbox`, and `clawback` — the
same actors as the [Builders](#builders) above.

The assembler returns a **fully-assembled, autofilled Batch — sign and submit it
as-is.** Its inner sequences are pinned to the values the proofs bind, so don't
overwrite or re-derive them (a second `client.autofill` is harmless — it preserves
already-set sequences — but there's no reason to call it). **Signing stays with
you:** when inners span several accounts, each non-outer account calls
`signMultiBatch` (combine two or more with `combineBatchSigners`), then the outer
account signs and submits:

```ts
import { signMultiBatch } from 'xrpl'

const batch = await prepareConfidentialBatch(client, {
  account: alice.classicAddress, // owns + signs the outer Batch
  inners: [
    { operation: 'send', account: alice.classicAddress, destination: carol.classicAddress, amount: 10n, senderKeypair: aliceKey, mptIssuanceID },
    { operation: 'send', account: bob.classicAddress, destination: carol.classicAddress, amount: 20n, senderKeypair: bobKey, mptIssuanceID },
  ],
})
signMultiBatch(bob, batch) // each non-outer participant authorizes its inner
const { tx_blob } = alice.sign(batch)
await client.submit(tx_blob)
```

The assembler handles every account/token combination uniformly — assigning each
account its position-derived inner sequences (mirroring `autofill`), threading
predicted balance state through repeated same-`(account, token)` operations,
shaping each inner (`tfInnerBatchTxn`, `Fee: '0'`), and autofilling the outer fee.

## Helpers

- `deriveConfidentialKeypair(seed?)` — derive an ElGamal keypair (see [Keys](#keys)).
- `getConfidentialBalance(client, account, mptIssuanceID, privateKey)` — decrypt
  and return an account's spendable confidential balance.
- `fetchMPToken`, `fetchMPTokenIssuance`, `getAccountSequence`, `accountIdHex` —
  lower-level ledger reads the builders use, exported for advanced callers.
- `loadMptCrypto()` — force-load the WASM module (e.g. to warm the cache before a
  latency-sensitive path); builders call it lazily on their own otherwise.
