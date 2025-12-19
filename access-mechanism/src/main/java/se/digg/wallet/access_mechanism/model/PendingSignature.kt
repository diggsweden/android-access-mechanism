package se.digg.wallet.access_mechanism.model

import com.nimbusds.jose.JWSObject

class PendingSignature internal constructor(
    val request: String,
    internal val jwsObject: JWSObject
)
