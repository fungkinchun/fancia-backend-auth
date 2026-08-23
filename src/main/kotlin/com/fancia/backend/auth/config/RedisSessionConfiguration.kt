package com.fancia.backend.auth.config

import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.connection.RedisConnectionFactory
import org.springframework.session.web.http.CookieSerializer
import org.springframework.session.web.http.DefaultCookieSerializer

@Configuration
@ConditionalOnProperty(prefix = "spring.data.redis", name = ["url"])
@ConditionalOnBean(RedisConnectionFactory::class)
class RedisSessionConfiguration(
    @Value("\${server.servlet.session.cookie.secure:true}") private val secureCookie: Boolean,
) {
    @Bean
    fun cookieSerializer(): CookieSerializer =
        DefaultCookieSerializer().apply {
            setCookieName("SESSION")
            setCookiePath("/")
            setUseHttpOnlyCookie(true)
            setSameSite("Lax")
            setUseSecureCookie(secureCookie)
        }
}
