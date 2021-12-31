package com.hhyun.keystoresample

import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.math.BigInteger
import java.nio.charset.Charset
import java.security.Key
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.RSAKeyGenParameterSpec
import java.util.*
import javax.crypto.Cipher
import javax.security.auth.x500.X500Principal

object EncryptManager {

    private const val KEY_STORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_STORE_ALGORITHM = "RSA"
    private const val CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding"

    private var keyAlias = ""
    private const val SPLIT_CHAR = "~"
    

    private fun getKeyStore(context: Context?): KeyStore? {
        if(context == null) return null

        this.keyAlias = context.packageName // 앱 패키지명

        try {
            val keyStore = KeyStore.getInstance(KEY_STORE_PROVIDER).apply {
                load(null)
            }

            if(!keyStore.containsAlias(keyAlias)) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) initAndroidM()
                else initAndroidK(context)
            }

            return keyStore

        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    private fun initAndroidM() {

        try {

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {

                val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEY_STORE_PROVIDER)

                kpg.initialize(
                    KeyGenParameterSpec
                        .Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4))
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                        .setDigests(KeyProperties.DIGEST_SHA512, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA256)
                        .setUserAuthenticationRequired(false)
                        .build()
                )

                kpg.generateKeyPair()

            }

        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun initAndroidK(context: Context) {

        try {

            if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {

                val start = Calendar.getInstance()
                val end = Calendar.getInstance()
                end.add(Calendar.YEAR, 25)

                val kpg = KeyPairGenerator.getInstance(KEY_STORE_ALGORITHM, KEY_STORE_PROVIDER)

                kpg.initialize(
                    KeyPairGeneratorSpec
                        .Builder(context)
                        .setKeySize(4096)
                        .setAlias(keyAlias)
                        .setSubject(X500Principal("CN=${keyAlias}"))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.time)
                        .setEndDate(end.time)
                        .build())

                kpg.generateKeyPair()

            }

        } catch (e: Exception) {
            e.printStackTrace()
        }

    }


    fun getEncrypted(context: Context?, data: String): String {

        var encrypted = ""
        val datas = data.chunked(500)           // 512 까지만 지원하므로, 긴 데이터를 암호화 하는 경우에는 500글자씩 끊어서 암호화 해야함.

        try {

            val keyStore = getKeyStore(context)
            var publicKey: Key? = null

            try {
                val keyEntry = keyStore?.getEntry(keyAlias, null)

                publicKey = if(keyEntry is KeyStore.PrivateKeyEntry) {
                    (keyEntry as KeyStore.PrivateKeyEntry).certificate.publicKey

                } else {
                    keyStore?.getCertificate(keyAlias)?.publicKey
                }

            } catch (e: Exception) {
                e.printStackTrace()

                try {
                    publicKey = keyStore?.getCertificate(keyAlias)?.publicKey

                } catch (e: Exception) {
                    e.printStackTrace()
                }

            }


            if(publicKey != null) {

                val encryptedArray = arrayListOf<String>()

                datas.forEach { t ->

                    val bytes = t.toByteArray(Charset.forName("UTF-8"))

                    val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
                    cipher.init(Cipher.ENCRYPT_MODE, publicKey)

                    val encryptedInfo = cipher.doFinal(bytes)
                    encryptedArray.add(Base64.encodeToString(encryptedInfo, Base64.NO_PADDING).trim())
                }

                encrypted = encryptedArray.joinToString(SPLIT_CHAR)
            }

        } catch (e: Exception) {
            e.printStackTrace()

        }

        return encrypted
    }

    fun getDecrypted(context: Context?, encrypted: String): String {

        var decrypted = ""

        try {

            val keyStore = getKeyStore(context)
            var privateKey: Key? = null

            try {
                val keyEntry = keyStore?.getEntry(keyAlias, null)

                privateKey = if(keyEntry is KeyStore.PrivateKeyEntry) {
                    (keyEntry as KeyStore.PrivateKeyEntry).privateKey

                } else {
                    keyStore?.getKey(keyAlias, null) as? PrivateKey
                }

            } catch (e: Exception) {
                e.printStackTrace()

                try {
                    keyStore?.getKey(keyAlias, null) as? PrivateKey

                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }


            if(privateKey != null) {

                val data = StringBuffer()

                encrypted.split(SPLIT_CHAR).forEach { t ->

                    val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
                    cipher.init(Cipher.DECRYPT_MODE, privateKey)

                    val bytes = t.toByteArray(Charset.forName("UTF-8"))
                    val decryptedBytes = Base64.decode(bytes, Base64.DEFAULT)
                    data.append(String(cipher.doFinal(decryptedBytes)))

                }

                decrypted = data.toString().trim()
            }

        } catch (e: Exception) {
            e.printStackTrace()
        }

        return decrypted

    }

}