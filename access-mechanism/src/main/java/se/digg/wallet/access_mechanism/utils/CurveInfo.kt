package se.digg.wallet.access_mechanism.utils

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import java.security.NoSuchAlgorithmException

internal enum class CurveInfo(
    val curveName: String,
    val jwsAlgorithm: JWSAlgorithm,
    val digestAlgorithm: String,
    val length: Int
) {
    P256(
        curveName = "P-256",
        jwsAlgorithm = JWSAlgorithm.ES256,
        digestAlgorithm = "SHA-256",
        length = 32
    ),
    P384(
        curveName = "P-384",
        jwsAlgorithm = JWSAlgorithm.ES384,
        digestAlgorithm = "SHA-384",
        length = 48
    ),
    P521(
        curveName = "P-521",
        jwsAlgorithm = JWSAlgorithm.ES512,
        digestAlgorithm = "SHA-512",
        length = 66
    );

    companion object {
        fun fromName(name: String): CurveInfo =
            entries.find { it.curveName == name }
                ?: throw NoSuchAlgorithmException("Unsupported curve: $name")

        fun fromAlgorithm(algorithm: JWSAlgorithm): CurveInfo =
            entries.find { it.jwsAlgorithm == algorithm }
                ?: throw JOSEException("Unsupported JWS algorithm: $algorithm")
    }
}