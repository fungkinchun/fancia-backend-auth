package com.fancia.backend.auth.security

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.Base64
import java.util.Date
import java.util.concurrent.atomic.AtomicReference

@Component
class AppleClientSecretGenerator(
    @Value("\${APPLE_CLIENT_ID:}") private val clientId: String,
    @Value("\${APPLE_TEAM_ID:}") private val teamId: String,
    @Value("\${APPLE_KEY_ID:}") private val keyId: String,
    @Value("\${APPLE_PRIVATE_KEY_PEM:}") private val privateKeyPem: String,
    @Value("\${APPLE_CLIENT_SECRET:}") private val staticClientSecret: String,
) {
    private val cached = AtomicReference<CachedSecret?>(null)

    fun isConfigured(): Boolean {
        if (staticClientSecret.isNotBlank()) return true
        return clientId.isNotBlank() &&
            teamId.isNotBlank() &&
            keyId.isNotBlank() &&
            privateKeyPem.isNotBlank()
    }

    fun generate(): String {
        staticClientSecret.trim().takeIf { it.isNotEmpty() }?.let { return it }

        require(isConfigured()) {
            "Sign in with Apple is not configured. Set APPLE_CLIENT_ID, APPLE_TEAM_ID, " +
                "APPLE_KEY_ID, and APPLE_PRIVATE_KEY_PEM (or APPLE_CLIENT_SECRET)."
        }

        val now = Instant.now()
        cached.get()?.takeIf { it.expiresAt.isAfter(now.plusSeconds(60)) }?.let { return it.value }

        val expiresAt = now.plusSeconds(TOKEN_TTL_SECONDS)
        val claims = JWTClaimsSet.Builder()
            .issuer(teamId.trim())
            .subject(clientId.trim())
            .audience("https://appleid.apple.com")
            .issueTime(Date.from(now))
            .expirationTime(Date.from(expiresAt))
            .build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .keyID(keyId.trim())
            .type(JOSEObjectType.JWT)
            .build()

        val jwt = SignedJWT(header, claims)
        jwt.sign(ECDSASigner(parsePrivateKey(privateKeyPem)))
        val value = jwt.serialize()
        cached.set(CachedSecret(value, expiresAt))
        return value
    }

    private fun parsePrivateKey(pem: String): ECPrivateKey {
        val normalized = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("\\n", "\n")
            .replace("\\r", "")
            .replace("\r", "")
            .replace("\n", "")
            .replace(" ", "")
            .trim()
        val der = Base64.getDecoder().decode(normalized)
        val keyFactory = KeyFactory.getInstance("EC")
        return keyFactory.generatePrivate(PKCS8EncodedKeySpec(der)) as ECPrivateKey
    }

    private data class CachedSecret(val value: String, val expiresAt: Instant)

    companion object {
        
        private const val TOKEN_TTL_SECONDS = 60L * 60L * 24L * 150L
    }
}
