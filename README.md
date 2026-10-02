# Boho for Arduino

[English](README.md) | [한국어](README.ko.md)

Boho provides data encryption and client–server authentication for Arduino.
The name **boho** means “protection.” It uses the same packet formats as
[Boho for JavaScript](https://github.com/remocons/boho), for communication with
Node.js servers and browser clients.

**Current version: 0.8.0**

Boho handles cryptographic packets. Your application supplies the transport,
message framing, buffers and connection lifecycle. It can be used with TCP,
Serial, WebSocket or MQTT payloads, and with stored data. For a complete messaging
client, see [IOSignal for Arduino](https://github.com/remocons/iosignal-arduino).

## Why Boho?

Boho focuses on systems where **you control both endpoints and can provision
their shared secrets**: a DIY Arduino device, a Node.js server and a web app you
develop yourself. If the endpoints can receive a secret through a trusted setup
process, shared-key authentication and symmetric encryption can be a suitable
way to protect their communication.

The practical task involves more than choosing an encryption algorithm. It also
requires authentication, packet formats and compatible device and browser code.
Boho brings these pieces together using SHA-256, an XOR keystream and shared-key
authentication. Its distinction is the common Arduino/JavaScript implementation
and application model; XOR and pre-shared keys themselves are established ideas.

### Where pre-shared keys fit

| Environment | Example provisioning path |
| --- | --- |
| Devices you build and install | Provision a device-specific secret over USB or a trusted serial setup tool |
| A web app and personal device | User-entered secrets obtained separately, or a trusted pairing process |
| Servers under common administration | Distribute secrets through SSH, an existing TLS channel or a secret management system |

These environments can establish trust without a certificate authority: trust
rests on the provisioning path and endpoint software. Key storage, rotation and
revocation still need to be managed. A key shared by many devices gives each
holder the same credential and increases the impact of a compromise. Publishing
a common secret in a browser JavaScript bundle does not keep it secret.

### XOR, one-time pads and a generated keystream

XOR is a simple reversible operation:

```text
Encryption: C = P XOR S
Decryption: P = C XOR S

P: plaintext, C: ciphertext, S: keystream
```

A true one-time pad (OTP) uses a uniformly random pad, independent of the
plaintext, as long as the data, kept secret and used only once. Under those
conditions it provides perfect secrecy. The practical difficulty is supplying a
new 1 MB secret pad to both endpoints for every 1 MB of data. Repeating a short
fixed key does not provide this property. Reusing a keystream exposes the
relationship `C1 XOR C2 = P1 XOR P2`.

Boho instead generates keystream blocks from a secret key and message-specific
values. For the usual `set_key()` path, the current construction is:

```text
K  = SHA256(input key)
B  = SHA256(K || salt12)
S1 = SHA256(B || LE32(1))
S2 = SHA256(B || LE32(2))
…
S  = S1 || S2 || …       // use only the plaintext length
C  = P XOR S
```

Here `||` means byte concatenation and `LE32` is a four-byte little-endian
integer. Each SHA-256 output supplies 32 bytes. A 70-byte message uses two full
blocks and the first six bytes of the third. Decryption regenerates the same
stream; it does not reverse the hash. Arduino computes the stream one block at
a time instead of storing a separate pad as large as the message. Packet and
application buffers are still required.

The 12-byte salt contains seconds (4 bytes), milliseconds (2), a counter (2)
and a nonce (4). These are not secret. **Hashing only public random values does
not produce a secret keystream**, because anyone can repeat the calculation.
The secret key supplies the secret input; repeating the same key and salt
repeats the stream.

“Virtual OTP” or “pseudo OTP” describes this generated stream, not the
information-theoretic guarantee of a true OTP. A hash does not add entropy to a
weak secret, and using standard SHA-256 does not establish the security of the
whole construction. Stream generation followed by XOR also appears in
[ChaCha20](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.4), but Boho's
hash-based construction is a different design.

XOR alone does not detect tampering. Current Boho data packets also carry the
first eight bytes of `SHA256(K || salt12 || plaintext)` as a verification tag.
The legacy `generateHMAC()` name does **not** mean standard HMAC. Applications
must use plaintext only after successful verification.

### How this relates to TLS

Typical certificate-based TLS authenticates a peer and establishes traffic keys
without requiring users to share a secret beforehand. It uses symmetric
encryption for application data. Even a client that has not logged in can
authenticate the server; this does not imply network anonymity.

On a small device, certificate-chain processing, trust roots, certificate
validity and clock management, renewal, handshake work and buffers can add
implementation and operating costs. For a developer already able to provision
keys, some of this machinery may be unnecessary for the intended application.

However, TLS itself supports **PSK-only and PSK with (EC)DHE**; it does not always
require public-key exchange or a third-party certificate system.
See [TLS 1.3 pre-shared keys](https://www.rfc-editor.org/rfc/rfc8446.html#section-2.2).
Boho's goal is a small shared-key packet and authentication implementation across
Arduino and JavaScript. This is not a claim that it outperforms every TLS or
standard symmetric implementation; that requires measurement on the target.

### From DIY devices to browser apps

Boho supplies encryption and authentication; IOSignal supplies connections and
message delivery between devices, Node.js and browsers. Connection credentials
and end-to-end data keys serve different purposes. To keep a relayed body
confidential from the relay, only the final endpoints should hold its separate
data key. Ordinary connection encryption is not automatically end-to-end
encryption, and routing information and traffic sizes can still be visible.

For normal web deployment, HTTPS protects delivery of the app code and WSS can
protect its connection, while Boho can separately encrypt application bodies.
If app code can be replaced, keys and plaintext can be stolen. E2E therefore
still depends on trusted endpoint code. Boho does not bypass browser mixed
content rules.

### Conditions to understand in the current implementation

- Use strong random secrets. A single SHA-256 in `set_key()` is not a slow
  password KDF, and Boho does not distribute or rotate keys for you.
- JavaScript uses `crypto.getRandomValues()`, but Arduino currently uses
  `micros()` for standalone-packet nonces and the authentication client nonce.
  `micros()` is not a cryptographic random source. Check for repeated key/salt
  combinations across restarts, devices and communication directions.
- A valid tag does not prove freshness. Challenge expiry, replay rejection,
  ordering and permission to execute a command belong to the calling system.
- Boho is a custom protocol, not a standard AEAD construction. Do not infer TLS
  or standard AEAD guarantees from its use of SHA-256. It does not provide
  forward secrecy if the long-term shared key is later compromised.

## Installation

Install this library and its **Crypto** dependency, which provides `SHA256.h`.
For local development or an unreleased version, install a ZIP of the library
through the Arduino IDE, or place its folder in your sketchbook's `libraries`
directory. Keep a single installed Boho copy to avoid selecting an older header.

```cpp
#include <Boho.h>
```

IOSignal now uses Boho as an external library and requires **Boho 0.8.0 or later**.
Do not copy `Boho.cpp` or `Boho.h` into the IOSignal `src/` directory.

## Quick start: encrypt and decrypt data

This standalone sketch uses a demonstration key. Replace it with your own shared
secret before use.

```cpp
#include <Boho.h>

Boho boho;
const char message[] = "Hello, Boho!";
uint8_t packet[sizeof(message) - 1 + MetaSize_ENC_PACK];
uint8_t plaintext[sizeof(message) - 1];

void setup() {
  Serial.begin(115200);
  boho.set_key("replace-with-your-shared-secret");

  const uint32_t packetLen = boho.encryptPack(
      packet, message, sizeof(message) - 1);
  if (packetLen == 0) {
    Serial.println("Encryption failed");
    return;
  }

  uint32_t plaintextLen = 0;
  if (boho.decryptPack(plaintext, packet, packetLen, plaintextLen)) {
    Serial.write(plaintext, plaintextLen);
    Serial.println();
  } else {
    Serial.println("Packet rejected");
  }
}

void loop() {}
```

Decrypted bytes are **not automatically NUL-terminated**. Use the returned length
for binary data or `Serial.write()`. If you need a C string, reserve an extra byte
and append the terminator after successful verification.

## Packet types and buffer sizes

| API | Use | Encryption output size | Requires connection authentication? |
| --- | --- | --- | --- |
| `encryptPack` / `decryptPack` | Independent data packet (`ENC_PACK`) | Plaintext + 25 bytes | No; requires a key |
| `encrypt_e2e` / `decrypt_e2e` | Independent packet with a separate data key | Plaintext + 25 bytes | No |
| `encrypt_488` / `decrypt_488` | Authenticated connection traffic (`ENC_488`) | Plaintext + 21 bytes | Yes |

Use `MetaSize_ENC_PACK` and `MetaSize_ENC_488` instead of hard-coded sizes.
Encryption returns the packet length, or `0` on failure. The caller must allocate
the output buffer; these APIs do not receive its capacity.

For decryption, allocate enough space for the plaintext. For a complete normal
packet, its received size minus the corresponding header size is an upper bound,
provided the packet is at least as long as the header. Enforce your application's
maximum packet size before allocating memory. Only consume the output on success.

### Empty messages and return values

Version 0.8.0 adds overloads that return success separately from the plaintext
length:

```cpp
bool decryptPack(void *out, const uint8_t *in, uint32_t len, uint32_t &plainLen);
bool decrypt_488(void *out, const uint8_t *in, uint32_t len, uint32_t &plainLen);
bool decrypt_e2e(void *out, const uint8_t *in, uint32_t len,
                 const char *key, uint32_t &plainLen);
```

A return value of `true` with `plainLen == 0` means a verified empty message.
The existing length-returning overloads remain available, but their `0` return
value cannot distinguish an empty plaintext from failure. Prefer the new overloads
when empty messages are valid in your application.

## Client–server authentication

Configure an ID and a nonempty shared key before authenticating:

```cpp
boho.set_id8("device1");
boho.set_key("replace-with-your-shared-secret");
// Alternative: boho.set_id_key("device1.replace-with-your-shared-secret");
```

`set_id8()` copies at most **8 bytes** and clears any previous trailing bytes.
`set_id_key()` requires a 1–8 byte ID, a `.` separator and a nonempty key; invalid
combined credentials clear the authentication state. Use the same ID and key in
the server's credential provider.

The normal authentication sequence is:

1. Receive a complete `SERVER_TIME_NONCE` packet from the server (13 bytes).
2. Call `auth_req(out, challenge, challengeLen)` and send its returned bytes.
   The output buffer must hold `MetaSize_AUTH_REQ` (45 bytes). Do not send if the
   returned length is zero.
3. Receive `AUTH_RES` and call `verify_auth_res(response, responseLen)`.
4. On success, `isAuthorized` becomes `true`; connection traffic can use
   `encrypt_488()` and `decrypt_488()`.

Do not set `isAuthorized = true` to bypass the handshake: the exchange also
establishes the nonces needed by both peers.

For deferred/manual login, `setClientTimeToServerTime(challenge, len)` caches a
validated challenge. After setting credentials, `auth_req(out)` can use that
cached challenge. It returns zero if no challenge or key is available. A cached
challenge belongs to its server connection; receive a new one after reconnecting.

`clearAuth()` clears the ID, key, nonces, cached challenge and authorization flag.
Set credentials again before starting another authentication exchange.

## End-to-end encryption and IOSignal

`encrypt_e2e(out, data, len, key)` produces an `ENC_PACK` using the supplied data
key and restores the original connection key afterward. The recipient uses
`decrypt_e2e(out, packet, packetLen, key, plainLen)` with the same data key.
An authenticated connection is not required for these standalone operations.

IOSignal adds its own `ENC_E2E` envelope: a connection-encrypted routing header
followed by the independently encrypted body. `decrypt_488()` accepts this envelope
and verifies only the routing header; the final recipient must separately verify
the body with `decrypt_e2e()`. Ordinary `ENC_488` packets require an exact declared
length, while `ENC_E2E` permits the trailing body.

## Time and memory

- `setTime(unixSeconds, milliseconds)` sets the local UTC clock.
- `refreshTime()` advances it using `millis()`, including timer rollover.
- `getUnixTime()` and `getMilTime()` return the last updated values. Call
  `refreshTime()` when reading time outside encryption operations.
- Authentication and `setClientTimeToServerTime()` can synchronize time from a
  server challenge.
- Packet-tag generation hashes the key/salt and payload incrementally, avoiding
  a temporary allocation proportional to the payload size.
- The `dynamic_alloc()` helper uses PSRAM on ESP32 when detected, and otherwise
  uses `malloc()`. Always check allocation results and size buffers for the board.

## Compatibility and security scope

Version 0.8.0 preserves the existing packet format while adding input validation,
ID parsing fixes, manual authentication, clock fixes and checked decryption APIs.
The implementation uses native integer byte order; the existing JS-compatible
packet format requires a little-endian target.

Boho uses a custom SHA-256-based construction. The legacy `generateHMAC()` name
refers to its protocol tag, not standard HMAC. It does not provide TLS or standard
AEAD guarantees. Key distribution, challenge expiry and replay rejection belong
to the application; successful packet verification alone does not prove freshness.
For E2E confidentiality from a relay server, keep the data key off that server.

Host tests cover malformed inputs and Arduino/JavaScript interoperability,
including authentication and ordinary/E2E traffic. These do not replace board
builds, SRAM checks or device communication tests.

## Examples and related projects

- [General encryption](examples/Boho-general-encryption/Boho-general-encryption.ino)
- [Unix time](examples/Boho-unix-time/Boho-unix-time.ino)
- [Boho for JavaScript](https://github.com/remocons/boho)
- [IOSignal for Arduino](https://github.com/remocons/iosignal-arduino)

## License

[MIT](LICENSE)
