package se.digg.wallet.access_mechanism.model

data class LoginStartResult(val loginRequest: String, val clientRegistration: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LoginStartResult

        if (loginRequest != other.loginRequest) return false
        if (!clientRegistration.contentEquals(other.clientRegistration)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = loginRequest.hashCode()
        result = 31 * result + clientRegistration.contentHashCode()
        return result
    }
}