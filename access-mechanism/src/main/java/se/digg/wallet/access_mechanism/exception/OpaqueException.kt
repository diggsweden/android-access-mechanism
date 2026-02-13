// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.exception

sealed class OpaqueException(message: String, cause: Throwable? = null) : Exception(message, cause) {

    class CryptoException(message: String, cause: Throwable? = null) : OpaqueException(message, cause)
    class ProtocolException(message: String, cause: Throwable? = null) : OpaqueException(message, cause)
    class InvalidInputException(message: String, cause: Throwable? = null) : OpaqueException(message, cause)

}
