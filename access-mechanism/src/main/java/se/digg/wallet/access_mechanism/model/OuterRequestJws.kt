package se.digg.wallet.access_mechanism.model

import androidx.annotation.VisibleForTesting
import com.nimbusds.jose.JWSObject

@JvmInline
value class OuterRequestJws(private val jws: JWSObject) {
    fun serialize(): String = jws.serialize()

    @VisibleForTesting
    internal fun unwrap(): JWSObject = jws
}
