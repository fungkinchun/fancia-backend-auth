package com.fancia.backend.auth.config

import com.fancia.backend.auth.core.user.UserMixin
import com.fancia.backend.auth.security.AppOidcUser
import com.fancia.backend.auth.security.AppOidcUserMixin
import com.fancia.backend.shared.user.core.entity.User
import org.springframework.beans.factory.BeanClassLoaderAware
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.annotation.Value
import org.springframework.beans.factory.config.BeanPostProcessor
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.core.Ordered
import org.springframework.core.PriorityOrdered
import org.springframework.data.redis.connection.RedisConnectionFactory
import org.springframework.data.redis.core.RedisOperations
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.data.redis.serializer.JacksonJsonRedisSerializer
import org.springframework.data.redis.serializer.RedisSerializer
import org.springframework.security.jackson.SecurityJacksonModules
import org.springframework.security.oauth2.client.jackson.OAuth2ClientJacksonModule
import org.springframework.security.oauth2.server.authorization.jackson.OAuth2AuthorizationServerJacksonModule
import org.springframework.session.data.redis.RedisSessionRepository
import org.springframework.session.web.http.CookieSerializer
import org.springframework.session.web.http.DefaultCookieSerializer
import tools.jackson.databind.JacksonModule
import tools.jackson.databind.json.JsonMapper
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator
import java.time.Duration

@Configuration
@ConditionalOnProperty(prefix = "spring.data.redis", name = ["url"])
@ConditionalOnBean(RedisConnectionFactory::class)
class RedisSessionConfiguration(
    @Value("\${server.servlet.session.cookie.secure:true}") private val secureCookie: Boolean,
    @Value("\${server.servlet.session.cookie.same-site:none}") private val sameSite: String,
) : BeanClassLoaderAware {
    private var classLoader: ClassLoader = RedisSessionConfiguration::class.java.classLoader

    override fun setBeanClassLoader(classLoader: ClassLoader) {
        this.classLoader = classLoader
    }

    @Bean
    fun cookieSerializer(): CookieSerializer =
        DefaultCookieSerializer().apply {
            setCookieName("SESSION")
            setCookiePath("/")
            setUseHttpOnlyCookie(true)
            setSameSite(sameSite)
            setUseSecureCookie(secureCookie)
        }

    @Bean(name = ["springSessionDefaultRedisSerializer"])
    fun springSessionDefaultRedisSerializer(): RedisSerializer<Any> {
        val typeValidator =
            BasicPolymorphicTypeValidator.builder()
                .allowIfSubType("com.fancia.backend.")
                .allowIfSubType("org.springframework.security.")
                .allowIfSubType("org.springframework.session.")
                .allowIfSubType("java.util.")
                .allowIfSubType("java.time.")
                .allowIfSubType("java.lang.")
                .allowIfSubType("[Ljava.lang.")

        val securityModules: List<JacksonModule> =
            SecurityJacksonModules.getModules(classLoader, typeValidator)

        val mapper =
            JsonMapper.builder()
                .addModules(securityModules)
                .addModule(OAuth2ClientJacksonModule())
                .addModule(OAuth2AuthorizationServerJacksonModule())
                .addMixIn(User::class.java, UserMixin::class.java)
                .addMixIn(AppOidcUser::class.java, AppOidcUserMixin::class.java)
                .build()

        @Suppress("UNCHECKED_CAST")
        return JacksonJsonRedisSerializer(mapper, Any::class.java) as RedisSerializer<Any>
    }

    @Bean(name = ["sessionRedisOperations"])
    fun sessionRedisOperations(
        connectionFactory: RedisConnectionFactory,
        @Qualifier("springSessionDefaultRedisSerializer") serializer: RedisSerializer<Any>,
    ): RedisOperations<String, Any> = jacksonSessionRedisTemplate(connectionFactory, serializer)

    @Bean
    @Primary
    fun sessionRepository(
        sessionRedisOperations: RedisOperations<String, Any>,
        @Value("\${spring.session.timeout:30m}") timeout: Duration,
        @Value("\${spring.session.redis.namespace:spring:session}") namespace: String,
    ): RedisSessionRepository = jacksonSessionRepository(sessionRedisOperations, timeout, namespace)

    @Bean
    fun redisSessionJacksonEnforcer(
        sessionRedisOperations: RedisOperations<String, Any>,
        @Value("\${spring.session.timeout:30m}") timeout: Duration,
        @Value("\${spring.session.redis.namespace:spring:session}") namespace: String,
    ): BeanPostProcessor =
        object : BeanPostProcessor, PriorityOrdered {
            override fun getOrder(): Int = Ordered.HIGHEST_PRECEDENCE

            override fun postProcessAfterInitialization(bean: Any, beanName: String): Any {
                if (bean is RedisSessionRepository) {
                    return jacksonSessionRepository(sessionRedisOperations, timeout, namespace)
                }
                return bean
            }
        }

    private fun jacksonSessionRedisTemplate(
        connectionFactory: RedisConnectionFactory,
        serializer: RedisSerializer<Any>,
    ): RedisTemplate<String, Any> {
        val template = RedisTemplate<String, Any>()
        template.connectionFactory = connectionFactory
        template.keySerializer = RedisSerializer.string()
        template.hashKeySerializer = RedisSerializer.string()
        template.valueSerializer = serializer
        template.hashValueSerializer = serializer
        template.defaultSerializer = serializer
        template.afterPropertiesSet()
        return template
    }

    private fun jacksonSessionRepository(
        sessionRedisOperations: RedisOperations<String, Any>,
        timeout: Duration,
        namespace: String,
    ): RedisSessionRepository =
        RedisSessionRepository(sessionRedisOperations).apply {
            setDefaultMaxInactiveInterval(timeout)
            setRedisKeyNamespace(namespace)
        }
}
