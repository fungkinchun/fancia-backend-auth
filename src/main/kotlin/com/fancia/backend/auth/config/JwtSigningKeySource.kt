package com.fancia.backend.auth.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import jakarta.annotation.PostConstruct
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

@Component
class JwtSigningKeySource(
    @Value("\${JWT_SIGNING_KEY_ID:}")
    private val keyId: String,
    @Value("\${JWT_SIGNING_PRIVATE_KEY_PEM:}")
    private val privateKeyPem: String,
    @Value("\${JWT_SIGNING_PUBLIC_KEY_PEM:}")
    private val publicKeyPem: String,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    private lateinit var signingKey: RSAKey
    private lateinit var jwkSource: JWKSource<SecurityContext>

    @PostConstruct
    fun initialize() {
        signingKey = loadSigningKey()
        jwkSource = ImmutableJWKSet(JWKSet(signingKey))
        log.info(
            "Loaded persisted OAuth2 JWT signing key (kid={}, bits={})",
            signingKey.keyID,
            signingKey.size(),
        )
    }

    fun createJwkSource(): JWKSource<SecurityContext> = jwkSource

    private fun loadSigningKey(): RSAKey {
        val normalizedKeyId = keyId.trim()
        require(normalizedKeyId.isNotEmpty()) {
            "JWT_SIGNING_KEY_ID is required (set via ${secretHint()})"
        }

        val normalizedPrivatePem = normalizePem(privateKeyPem)
        require(normalizedPrivatePem.isNotEmpty()) {
            "JWT_SIGNING_PRIVATE_KEY_PEM is required (set via ${secretHint()})"
        }

        val privateKey = parsePrivateKeyPem(normalizedPrivatePem, "JWT_SIGNING_PRIVATE_KEY_PEM")
        val publicKey = publicKeyFromPrivate(privateKey)

        val keySize = publicKey.modulus.bitLength()
        require(keySize >= MIN_RSA_KEY_SIZE) {
            "JWT signing key must be at least $MIN_RSA_KEY_SIZE bits (got $keySize)"
        }

        val normalizedPublicPem = normalizePem(publicKeyPem)
        if (normalizedPublicPem.isNotEmpty()) {
            val configuredPublicKey = parsePublicKeyPem(normalizedPublicPem, "JWT_SIGNING_PUBLIC_KEY_PEM")
            if (configuredPublicKey.modulus != publicKey.modulus) {
                throw IllegalStateException(
                    "JWT_SIGNING_PUBLIC_KEY_PEM does not match JWT_SIGNING_PRIVATE_KEY_PEM"
                )
            }
        }

        return RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(normalizedKeyId)
            .build()
    }

    private fun parsePrivateKeyPem(pem: String, propertyName: String): RSAPrivateKey {
        if (!pem.contains(PKCS8_PRIVATE_KEY_HEADER)) {
            throw IllegalStateException(
                "$propertyName must be PKCS#8 PEM (-----BEGIN PRIVATE KEY-----). " +
                    "Convert with: openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.pkcs8.pem",
            )
        }

        return try {
            val spec = PKCS8EncodedKeySpec(decodePemBody(pem))
            KeyFactory.getInstance(RSA_ALGORITHM).generatePrivate(spec) as RSAPrivateKey
        } catch (e: Exception) {
            throw IllegalStateException("Failed to parse $propertyName", e)
        }
    }

    private fun parsePublicKeyPem(pem: String, propertyName: String): RSAPublicKey {
        if (!pem.contains(PUBLIC_KEY_HEADER)) {
            throw IllegalStateException(
                "$propertyName must be SPKI PEM (-----BEGIN PUBLIC KEY-----)",
            )
        }

        return try {
            val spec = X509EncodedKeySpec(decodePemBody(pem))
            KeyFactory.getInstance(RSA_ALGORITHM).generatePublic(spec) as RSAPublicKey
        } catch (e: Exception) {
            throw IllegalStateException("Failed to parse $propertyName", e)
        }
    }

    private fun publicKeyFromPrivate(privateKey: RSAPrivateKey): RSAPublicKey {
        val crtKey =
            privateKey as? RSAPrivateCrtKey
                ?: throw IllegalStateException("JWT signing private key must be an RSA CRT key")

        return try {
            val spec = RSAPublicKeySpec(crtKey.modulus, crtKey.publicExponent)
            KeyFactory.getInstance(RSA_ALGORITHM).generatePublic(spec) as RSAPublicKey
        } catch (e: Exception) {
            throw IllegalStateException("Failed to derive public key from JWT signing private key", e)
        }
    }

    private fun decodePemBody(pem: String): ByteArray {
        val body =
            pem.lines()
                .filter { line ->
                    !line.startsWith("-----BEGIN") && !line.startsWith("-----END")
                }
                .joinToString("")
        return Base64.getDecoder().decode(body)
    }

    private fun secretHint(): String = "ENV/PROJECT_NAME/oauth2 Secrets Manager secret"

    companion object {
        private const val RSA_ALGORITHM = "RSA"
        private const val MIN_RSA_KEY_SIZE = 2048
        private const val PKCS8_PRIVATE_KEY_HEADER = "BEGIN PRIVATE KEY"
        private const val PUBLIC_KEY_HEADER = "BEGIN PUBLIC KEY"

        internal fun normalizePem(value: String): String =
            value.trim()
                .removeSurrounding("\"")
                .replace("\\n", "\n")
                .replace("\r\n", "\n")
                .trim()
    }
}
