# Protocol

Versioned, strongly-typed JSON envelope (`NetworkMessage`):

- `version`, `messageId`, `senderId`, `transactionId?`
- `timestamp`, `nonce`
- `type` (see `MessageType`)
- `payload` (type-specific JSON)
- `authentication` (detached HMAC tag, computed over `signedData()`)

Message types: HELLO, AUTHENTICATE, PING/PONG, GET_STATUS/STATUS,
RELEASE_DEVICES/DEVICES_RELEASED, CONNECT_DEVICES/DEVICES_CONNECTED,
SWITCH_COMPLETE/SWITCH_FAILED, BUSY, ERROR.

Every command in a switch carries the same `transactionId`.
