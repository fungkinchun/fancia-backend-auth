package com.fancia.backend.auth.config

import io.lettuce.core.ClientOptions
import io.lettuce.core.SocketOptions
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.data.redis.connection.RedisPassword
import org.springframework.data.redis.connection.RedisStandaloneConfiguration
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory
import java.net.URI
import java.time.Duration

@Configuration
@ConditionalOnProperty(prefix = "spring.data.redis", name = ["url"])
class RedisConnectionConfiguration(
    @Value("\${spring.data.redis.url}") private val redisUrl: String,
    @Value("\${spring.data.redis.timeout:3s}") private val commandTimeout: Duration,
    @Value("\${spring.data.redis.connect-timeout:5s}") private val connectTimeout: Duration,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @Bean
    @Primary
    fun lettuceConnectionFactory(): LettuceConnectionFactory {
        val uri = URI(normalizeRedisUrl(redisUrl))
        val host = uri.host ?: error("REDIS_URL is missing a host")
        val port = if (uri.port > 0) uri.port else 6379
        val useSsl = uri.scheme.equals("rediss", ignoreCase = true)

        val standalone = RedisStandaloneConfiguration(host, port).apply {
            uri.userInfo?.let { userInfo ->
                val parts = userInfo.split(":", limit = 2)
                when (parts.size) {
                    1 -> password = RedisPassword.of(parts[0])
                    2 -> {
                        // Upstash uses username "default" + password token
                        if (parts[0].isNotBlank()) {
                            username = parts[0]
                        }
                        if (parts[1].isNotBlank()) {
                            password = RedisPassword.of(parts[1])
                        }
                    }
                }
            }
        }

        val clientOptions =
            ClientOptions.builder()
                .socketOptions(
                    SocketOptions.builder()
                        .connectTimeout(connectTimeout)
                        .keepAlive(true)
                        .build(),
                )
                .build()

        val clientConfigBuilder =
            LettuceClientConfiguration.builder()
                .commandTimeout(commandTimeout)
                .clientOptions(clientOptions)

        val clientConfig =
            if (useSsl) {
                clientConfigBuilder.useSsl().build()
            } else {
                clientConfigBuilder.build()
            }

        log.info(
            "Configuring Redis session store host={} port={} ssl={}",
            host,
            port,
            useSsl,
        )
        if (!useSsl) {
            log.warn(
                "REDIS_URL is not rediss:// — Upstash requires TLS. " +
                    "Use the TLS URL from the Upstash console (rediss://...).",
            )
        }

        return LettuceConnectionFactory(standalone, clientConfig).apply {
            afterPropertiesSet()
        }
    }

    private fun normalizeRedisUrl(raw: String): String {
        val trimmed = raw.trim()
        // Common copy/paste: Upstash host with redis:// instead of rediss://
        if (trimmed.startsWith("redis://", ignoreCase = true) &&
            trimmed.contains("upstash.io", ignoreCase = true)
        ) {
            return "rediss://" + trimmed.substringAfter("://")
        }
        return trimmed
    }
}
