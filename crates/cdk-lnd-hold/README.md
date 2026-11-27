# CDK LND hold invoice backend

`MintPayment` backend that serves the `bolt11_hold` payment method through
`cdk-payment-processor`.

It reuses the `cdk-lnd` TLS and macaroon gRPC transport, creates hold invoices
with `invoicesrpc.AddHoldInvoice`, and follows each one with
`invoicesrpc.SubscribeSingleInvoice`. A payment is only reported once LND has
settled the invoice.

When LND accepts the full amount, the backend publishes the quote as `HELD` with
a `settle_deadline`: the lowest accepted HTLC expiry height minus
`settle_margin_blocks`. Once the block height from `lnrpc.Lightning.GetInfo`
passes that deadline, it cancels the held invoice with
`invoicesrpc.CancelInvoice` and reports `CANCELLED`.

LND cancels accepted hold invoices on its own when `height +
invoices.holdexpirydelta` reaches the lowest accepted HTLC expiry height
(`invoices/invoice_expiry_watcher.go`). That default is
`DefaultIncomingBroadcastDelta + 2`, so 18 on LND v0.21.8. The backend therefore
refuses to start unless `settle_margin_blocks` is larger than
`lnd_hold_expiry_delta`, which keeps `settle_deadline` strictly below the height
where LND gives up. Defaults are `settle_margin_blocks = 22` and
`lnd_hold_expiry_delta = 18`; set them with
`CDK_PAYMENT_PROCESSOR_LND_HOLD_SETTLE_MARGIN_BLOCKS` and
`CDK_PAYMENT_PROCESSOR_LND_HOLD_EXPIRY_DELTA` to match a non-default LND.

Hold state is kept in memory. On startup the backend pages through LND's pending
invoices with `lnrpc.Lightning.ListInvoices` and resumes following them, so a
held invoice is still cancelled after a restart even if the mint never checks
that quote again.

The recovery lists every pending invoice of the node, and `lnrpc.Invoice` has no
flag that marks a hold invoice, so this backend assumes a dedicated mint node.
On a node shared with another component's invoices it also follows those, and it
cancels any of them it sees accepted once their HTLC expiry passes the deadline.

Run it with `CDK_PAYMENT_PROCESSOR_BACKEND=LND_HOLD`.
