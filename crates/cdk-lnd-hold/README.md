# CDK LND hold invoice backend

`MintPayment` backend that serves the `bolt11_hold` payment method through
`cdk-payment-processor`.

It reuses the `cdk-lnd` TLS and macaroon gRPC transport, creates hold invoices
with `invoicesrpc.AddHoldInvoice`, and reads their state with
`lnrpc.Lightning.LookupInvoice`. A payment is only reported once LND has settled
the invoice.

Run it with `CDK_PAYMENT_PROCESSOR_BACKEND=LND_HOLD`.
