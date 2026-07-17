package com.zkvault.wearos

import android.app.Activity
import android.os.Bundle
import androidx.wear.widget.WearableRecyclerView
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// MARK: - WearOS TOTP Display
//
// Minimal WearOS activity that displays TOTP codes.
// Secrets are synced via Wearable Data Layer API from the phone companion app.

data class TotpAccount(
    val id: String,
    val label: String,
    val secret: String,  // Base32-encoded
    val issuer: String
)

class TotpListActivity : Activity() {

    private lateinit var recyclerView: WearableRecyclerView
    private val accounts = mutableListOf<TotpAccount>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_totp_list)

        recyclerView = findViewById(R.id.recycler_view)
        // Load accounts from Data Layer API (placeholder)
        accounts.addAll(loadAccounts())
        recyclerView.adapter = TotpAdapter(accounts)
    }

    private fun loadAccounts(): List<TotpAccount> {
        // TODO: Sync from phone via Wearable Data Layer API
        return emptyList()
    }

    companion object {
        /**
         * Generates a TOTP code (RFC 6238) for a given base32 secret.
         */
        fun generateTotp(secretBase32: String, timeStep: Long = 30L, digits: Int = 6): String {
            val secret = base32Decode(secretBase32)
            val counter = System.currentTimeMillis() / 1000 / timeStep
            val counterBytes = ByteArray(8).also {
                var c = counter
                for (i in 7 downTo 0) {
                    it[i] = (c and 0xFF).toByte()
                    c = c shr 8
                }
            }

            val mac = Mac.getInstance("HmacSHA1")
            mac.init(SecretKeySpec(secret, "HmacSHA1"))
            val hash = mac.doFinal(counterBytes)

            val offset = hash[hash.size - 1].toInt() and 0x0f
            val code = ((hash[offset].toInt() and 0x7f) shl 24) or
                       ((hash[offset + 1].toInt() and 0xff) shl 16) or
                       ((hash[offset + 2].toInt() and 0xff) shl 8) or
                       (hash[offset + 3].toInt() and 0xff)

            val otp = code % Math.pow(10.0, digits.toDouble()).toInt()
            return otp.toString().padStart(digits, '0')
        }

        private fun base32Decode(encoded: String): ByteArray {
            val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            val cleaned = encoded.uppercase().filter { it in chars }
            val bits = mutableListOf<Boolean>()
            for (ch in cleaned) {
                val index = chars.indexOf(ch)
                for (i in 4 downTo 0) {
                    bits.add(((index shr i) and 1) == 1)
                }
            }
            val bytes = mutableListOf<Byte>()
            for (i in 0 until bits.size - 7 step 8) {
                var byte = 0
                for (j in 0 until 8) {
                    byte = (byte shl 1) or (if (bits[i + j]) 1 else 0)
                }
                bytes.add(byte.toByte())
            }
            return bytes.toByteArray()
        }
    }
}
