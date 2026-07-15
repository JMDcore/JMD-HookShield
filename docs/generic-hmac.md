# Generic HMAC protocol

The Generic adapter exists for local testing and integrations that can implement a small signing contract.

Required headers:

```text
X-HookShield-Signature: sha256=<lowercase hex HMAC>
X-HookShield-Timestamp: <Unix seconds>
X-HookShield-Delivery: <provider-unique identifier>
```

The signed byte sequence is:

```text
<timestamp>.<delivery-id>.<raw request body bytes>
```

Compute HMAC-SHA256 with the endpoint secret. HookShield checks the signature in constant time, requires the timestamp to fall inside the configured tolerance (300 seconds by default), and rejects a reused delivery identifier as a duplicate/replay. The timestamp and identifier are part of the MAC, so changing either invalidates the signature.
