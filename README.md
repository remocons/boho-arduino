# Boho for Arduino

Boho provides data encryption and client–server authentication for Arduino.
The name **boho** means “protection.” It uses the same packet formats as
[Boho for JavaScript](https://github.com/remocons/boho), for communication with
Node.js servers and browser clients.

**Current version: 0.8.0**

Boho handles cryptographic packets. Your application supplies the transport,
message framing, buffers and connection lifecycle. It can be used with TCP,
Serial, WebSocket or MQTT payloads, and with stored data. For a complete messaging
client, see [IOSignal for Arduino](https://github.com/remocons/iosignal-arduino).

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
