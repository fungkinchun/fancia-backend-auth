package com.fancia.backend.auth.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.stereotype.Component

@Component
class OAuth2LoginFailureHandler : SimpleUrlAuthenticationFailureHandler("/login?oauth2Error") {
    private val log = LoggerFactory.getLogger(javaClass)

    override fun onAuthenticationFailure(
        request: HttpServletRequest,
        response: HttpServletResponse,
        exception: AuthenticationException,
    ) {
        if (exception is OAuth2AuthenticationException) {
            log.error(
                "OAuth2 login failed: error={}, description={}, uri={}",
                exception.error.errorCode,
                exception.error.description,
                exception.error.uri,
                exception,
            )
        } else {
            log.error("OAuth2 login failed: {}", exception.message, exception)
        }
        super.onAuthenticationFailure(request, response, exception)
    }
}
