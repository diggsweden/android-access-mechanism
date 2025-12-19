package se.digg.wallet.access_mechanism.exception

sealed class OpaqueException(message: String, cause: Throwable? = null) : Exception(message, cause) {

    class CryptoException(message: String, cause: Throwable? = null) : OpaqueException(message, cause)
    class ProtocolException(message: String, cause: Throwable? = null) : OpaqueException(message, cause)
    class InvalidInputException(message: String, cause: Throwable? = null) : OpaqueException(message, cause)

}
