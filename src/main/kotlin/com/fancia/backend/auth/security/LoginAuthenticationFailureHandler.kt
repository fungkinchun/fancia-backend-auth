package com.fancia.backend.auth.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.WebAttributes
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler

class LoginAuthenticationFailureHandler : SimpleUrlAuthenticationFailureHandler("/login?error") {
    override fun onAuthenticationFailure(
        request: HttpServletRequest,
        response: HttpServletResponse,
        exception: AuthenticationException,
    ) {
        request.getSession(false)?.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION)
        super.onAuthenticationFailure(request, response, exception)
    }
}
