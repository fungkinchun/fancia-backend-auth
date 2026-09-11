package com.fancia.backend.auth.config

import org.springframework.beans.factory.config.BeanPostProcessor
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.session.Session
import org.springframework.session.SessionRepository
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes

@Configuration
class SkipStaticResourceSessionConfiguration {

    @Bean
    fun skipStaticResourceSessionRepositoryPostProcessor(): BeanPostProcessor =
        object : BeanPostProcessor {
            override fun postProcessAfterInitialization(bean: Any, beanName: String): Any {
                if (bean is SessionRepository<*> && bean !is SkipStaticResourceSessionRepository<*>) {
                    @Suppress("UNCHECKED_CAST")
                    return SkipStaticResourceSessionRepository(bean as SessionRepository<Session>)
                }
                return bean
            }
        }
}

class SkipStaticResourceSessionRepository<S : Session>(
    private val delegate: SessionRepository<S>,
) : SessionRepository<S> {

    override fun createSession(): S = delegate.createSession()

    override fun save(session: S) {
        if (isStaticResourceRequest()) return
        delegate.save(session)
    }

    override fun findById(id: String): S? {
        if (isStaticResourceRequest()) return null
        return delegate.findById(id)
    }

    override fun deleteById(id: String) {
        if (isStaticResourceRequest()) return
        delegate.deleteById(id)
    }

    private fun isStaticResourceRequest(): Boolean {
        val request =
            (RequestContextHolder.getRequestAttributes() as? ServletRequestAttributes)?.request
                ?: return false
        val path = request.servletPath ?: request.requestURI
        return STATIC_PREFIXES.any { path.startsWith(it) }
    }

    companion object {
        private val STATIC_PREFIXES = listOf("/css/", "/img/")
    }
}
