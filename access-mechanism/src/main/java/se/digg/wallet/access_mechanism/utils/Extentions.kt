// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.utils

internal fun ByteArray.toHexString(): String =
    this.joinToString("") { "%02x".format(it) }
