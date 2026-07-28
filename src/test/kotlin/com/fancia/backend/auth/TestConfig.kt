package com.fancia.backend.auth

import com.nimbusds.jose.jwk.RSAKey
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.boot.testcontainers.service.connection.ServiceConnection
import org.springframework.context.annotation.Bean
import org.springframework.test.context.DynamicPropertyRegistrar
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.utility.DockerImageName
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64

@TestConfiguration(proxyBeanMethods = false)
class TestConfig {
    @Bean
    @ServiceConnection
    fun postgres(): PostgreSQLContainer<*> {
        return PostgreSQLContainer(
            DockerImageName.parse("postgis/postgis:16-3.4-alpine")
                .asCompatibleSubstituteFor("postgres")
        )
            .withDatabaseName("testdb")
            .withUsername("test")
            .withPassword("test")
    }

    @Bean
    fun testProperties(): DynamicPropertyRegistrar =
        DynamicPropertyRegistrar { registry ->
            registry.add("spring.flyway.placeholders.gis_admin_password") { "test-gis-admin" }

            val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
            val rsaKey =
                RSAKey.Builder(keyPair.public as RSAPublicKey)
                    .privateKey(keyPair.private as RSAPrivateKey)
                    .keyID("test-jwt-signing-key")
                    .build()

            registry.add("JWT_SIGNING_KEY_ID") { rsaKey.keyID }
            registry.add("JWT_SIGNING_PRIVATE_KEY_PEM") { rsaPrivateKeyToPem(keyPair.private as RSAPrivateKey) }
        }

    private fun rsaPrivateKeyToPem(privateKey: RSAPrivateKey): String {
        val encoded = Base64.getEncoder().encodeToString(privateKey.encoded)
        val body = encoded.chunked(64).joinToString("\n")
        return "-----BEGIN PRIVATE KEY-----\n$body\n-----END PRIVATE KEY-----"
    }
}