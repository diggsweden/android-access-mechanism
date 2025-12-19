package se.digg.wallet.access_mechanism.utils

import com.nimbusds.jose.jwk.JWK
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import java.time.Duration
import java.time.Instant
import java.util.Base64

internal val AppJson = Json {
    encodeDefaults = true
    explicitNulls = false
}

internal object InstantIso8601Serializer : KSerializer<Instant> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Instant", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Instant) =
        encoder.encodeString(value.toString())

    override fun deserialize(decoder: Decoder): Instant = Instant.parse(decoder.decodeString())
}

internal object DurationIso8601Serializer : KSerializer<Duration> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Duration", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: Duration
    ) =
        encoder.encodeString(value.toString())

    override fun deserialize(decoder: Decoder): Duration =
        Duration.parse(decoder.decodeString())

}

internal object Base64ByteArraySerializer : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Base64ByteArray", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteArray) {
        encoder.encodeString(Base64.getEncoder().encodeToString(value))
    }

    override fun deserialize(decoder: Decoder): ByteArray {
        return Base64.getDecoder().decode(decoder.decodeString())
    }
}

internal object JwkSerializer : KSerializer<JWK> {
    override val descriptor: SerialDescriptor = JsonObject.serializer().descriptor

    override fun serialize(encoder: Encoder, value: JWK) {
        val jsonEncoder = encoder as? JsonEncoder
            ?: throw IllegalStateException("This serializer can be used only with Json format")
        val element = AppJson.parseToJsonElement(value.toJSONString())
        jsonEncoder.encodeJsonElement(element)
    }

    override fun deserialize(decoder: Decoder): JWK {
        val jsonDecoder = decoder as? JsonDecoder
            ?: throw IllegalStateException("This serializer can be used only with Json format")
        val element = jsonDecoder.decodeJsonElement()
        return JWK.parse(element.toString())
    }
}
