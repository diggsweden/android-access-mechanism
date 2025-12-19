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

## Usage

All operations are exposed through a single entry point:

    se.digg.wallet.access_mechanism.api.OpaqueClient

### Initialization

Instantiate `OpaqueClient` with the following parameters:

| Parameter              | Description                                                          |
|------------------------|----------------------------------------------------------------------|
| `serverPublicKey`      | The server's EC public key                                           |
| `clientPrivateKey`     | Client EC private key (should be stored in secure hardware)          |
| `pinStretchPrivateKey` | Private key for PIN stretching (should be stored in secure hardware) |
| `clientIdentifier`     | Unique client identifier                                             |
| `serverIdentifier`     | Server identifier                                                    |
| `opaqueContext`        | OPAQUE protocol context                                              |

---

### Register PIN

Register a PIN for the device. This is a two-step process that needs to be performed once before a
session can be created.

1. Call `registrationStart(pin)` → returns `registrationRequest` + `clientRegistration`.
2. Send `registrationRequest` to the server.
3. Call `registrationFinish()` with the `pin`,an `authorizationCode`, the server's response and
   `clientRegistration` from step 1.
4. Send `registrationUpload` from step 3 to the server.
5. *(Optional)* Call `decryptStatus()` with the server's response and verify it returns `"OK"`.

> `authorizationCode` is a temporary code that will be set during onboarding. Its use is still TBD.
> During development any non-empty ByteArray can be passed.
---

### Create Session

A new session will be required for each HSM operation.

1. Call `loginStart(pin)` → returns `loginRequest` + `clientRegistration`.
2. Send `loginRequest` to the server.
3. Call `loginFinish()` with the `pin`, the server's response and `clientRegistration` from step 1.
4. Send `loginFinishRequest` from step 3 to the server.
5. If step 4 is successful, the sessionKey is ready to be used.

> The **`sessionKey`** and **`pakeSessionId`** are available from step 3. These are required for
> all later operations.

---

### HSM Key Management

Once a session is established, you can manage HSM-backed keys on the server. All operations below
require a `sessionKey` and `pakeSessionId` from [Create Session](#create-session).

#### Create a HSM Key

1. val request = client.createHsmKey(sessionKey, pakeSessionId).
2. Send the request to the server.
3. Call `decryptPayload()` with the response from step 2 and the `sessionKey` to decrypt the payload
   from the server.

#### List Keys

1. val request = client.listHsmKeys(sessionKey, pakeSessionId).
2. Send the request to the server
3. Call `decryptKeys()` with the response from step 2 and the `sessionKey`) to get a list of
   available keys.

#### Delete a Key

1. val request = client.deleteHsmKey(sessionKey, pakeSessionId, `kid`).
2. Send the request to the server.
3. Call 'decryptPayload()' with the response from step 2 and the `sessionKey` to verify the deletion
   was successful.

---

### HSM Signing

Sign a payload using a server-side HSM key. This is a two-step process:

1. Call `signWithHsm()` with the `sessionKey`, `pakeSessionId`, `kid` (keyId of the key to use) and
   the payload to sign. Returns a `PendingSignature` containing the local state and the request.
2. Send the request to the server.
3. Call `decryptSign()` with the `sessionKey`, `PendingSignature` from step 1, the response
   from step 2, and the HSM keys public key. Returns a fully signed and verified JWS.

---

### Decrypting Server Responses

| Method             | Use case                                             |
|--------------------|------------------------------------------------------|
| `decryptStatus()`  | Unwrap a PAKE response and read its status           |
| `decryptPayload()` | Decrypt a session-encrypted response as raw JSON     |
| `decryptKeys()`    | Decrypt and deserialize a `listHsmKeys` response     |
| `decryptSign()`    | Decrypt a signing response and assemble a signed JWS |

---

## Publishing

Production publishing is **TBD**.

## License

TBD
