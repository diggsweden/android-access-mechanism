# Access Mechanism — Android Library

An Android library for secure device authentication and server communication. It implements the
[OPAQUE](https://datatracker.ietf.org/doc/rfc9807/) protocol for PIN-based authentication and
provides an encrypted channel for HSM key
management and signing operations once a session is established.

## Getting Started

### Local Build

Build a fat AAR and publish to your local Maven repository:

    ./gradlew publishToMavenLocal

### Installation

1. Ensure `mavenLocal()` is listed in your app's repository configuration:

        repositories {
            mavenLocal()
            // ... other repositories ...
        }

2. Add the dependency to your app-level `build.gradle.kts`:

        implementation("se.digg.wallet:access-mechanism:<version>")

## Dependencies

### opaque_ke_uniffi

This library depends on `opaque_ke_uniffi-release.aar`, located in `access-mechanism/libs/`. This
binary contains the core OPAQUE cryptographic logic and is built from
the [opaque_ke_uniffi](https://github.com/diggsweden/opaque_ke_uniffi) repository.

The build script is configured to extract JNI libraries and classes from this AAR to bundle them
into the final output, creating a "fat" AAR that is straightforward to consume.

## Testing

### Integration tests

The integration tests exercise the real OPAQUE bindings on the host JVM (no emulator). This
requires a host-native slice, `opaque_ke_uniffi-desktop.jar`, in `access-mechanism/libs/`.

This jar is **architecture-specific and is not committed** — each platform needs its own build.
Produce it with `make desktop` in the
[opaque_ke_uniffi](https://github.com/diggsweden/opaque_ke_uniffi) repository, then copy the
result into `access-mechanism/libs/`.

The build adds the jar to the test classpath only when it is present. Without it, `./gradlew test`
still compiles and runs, but the integration tests `Assume`-skip rather than fail. Because a
missing jar silently skips these tests, CI should build (or assert the presence of) the slice so
runs are guaranteed to exercise the real bindings.

## Usage

All operations are exposed through a single entry point:

    se.digg.wallet.access_mechanism.api.OpaqueClient

Every operation is a `suspend` function. The client drives the OPAQUE and session-encryption
protocols internally; the host app only supplies the network layer.

### Transport

The library does not ship an HTTP client. Implement `OpaqueTransport` to connect it to your backend:

```kotlin
interface OpaqueTransport {
    suspend fun registerState(publicKey: ECPublicKey, overwrite: Boolean, ttl: String? = null): StateResponse
    suspend fun perform(request: HSMRequest, operation: HSMOperationType): String
}
```

- `registerState` registers the device's public key and returns the server's `StateResponse`.
- `perform` sends an `HSMRequest` (`clientId` + `outerRequestJws`) and returns the server's compact
  JWS response. `operation` tells the transport which HSM operation the request belongs to.

### Initialization

On first launch, create the client. This registers the device with the server and fetches the
server parameters:

```kotlin
val client = OpaqueClient.create(
    clientKeyPair = clientKeyPair,               // should be stored in secure hardware
    pinStretchPrivateKey = pinStretchPrivateKey, // should be stored in secure hardware
    transport = transport
)
```

Optional parameters are `opaqueContext` (default `"RPS-Ops"`), `ttl`, `overwrite` and `dispatcher`
(default `Dispatchers.IO`).

Persist `client.serverParameters`. On later launches, rebuild the client from them without a
network call:

```kotlin
val client = OpaqueClient.resume(transport, savedServerParameters, clientKeyPair, pinStretchPrivateKey)
```

---

### Register PIN

Register a PIN once, directly after `create()`. The one-time authorization code from the state
response is used and then discarded, so `registration()` fails on a client built with `resume()`.

```kotlin
val exportKey: ByteArray = client.registration(pin)
```

---

### Create Session

Authenticate with the PIN to establish a session. Every operation below requires an active session.

```kotlin
val exportKey: ByteArray = client.authenticate(pin)  // optional: task = "general"
```

### Change PIN

Requires an active session.

```kotlin
val exportKey: ByteArray = client.changePin(newPin)
```

---

### HSM Key Management

| Call                | Returns                                               |
|---------------------|-------------------------------------------------------|
| `createHsmKey()`    | `KeyResponse`: public key of a new P-256 key          |
| `listHsmKeys()`     | `List<KeyInfo>`: public key and creation time per key |
| `deleteHsmKey(kid)` | `Unit`                                                |

---

### HSM Signing

| Call                                                   | Returns                                                     |
|--------------------------------------------------------|-------------------------------------------------------------|
| `sign(kid, data)`                                      | `SignatureResponse`: P1363 signature over SHA-256 of `data` |
| `signJws(kid, payload, curve = "P-256", publicHsmKey)` | Compact JWS, verified against `publicHsmKey`                |

---

### Errors

Failures are thrown as subclasses of `OpaqueException`: `CryptoException`, `ProtocolException` or
`InvalidInputException`. Calling a session operation before `authenticate()` throws
`IllegalStateException`.

---

## Publishing

Production publishing is **TBD**.

## License

TBD
