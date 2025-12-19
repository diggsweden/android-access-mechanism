package se.digg.wallet.access_mechanism.utils

internal fun ByteArray.toHexString(): String =
    this.joinToString("") { "%02x".format(it) }
