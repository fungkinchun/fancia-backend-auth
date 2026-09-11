package com.fancia.backend.auth.security

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.web.filter.OncePerRequestFilter

class AppleSignInUserCaptureFilter : OncePerRequestFilter() {
    private val log = LoggerFactory.getLogger(javaClass)

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        if (request.method.equals("POST", ignoreCase = true)) {
            val userJson = request.getParameter("user")
            val code = request.getParameter("code")
            if (!userJson.isNullOrBlank() && !code.isNullOrBlank()) {
                request.setAttribute(AppleSignInUser.REQUEST_ATTRIBUTE, userJson)
                log.info("Captured Apple Sign In user form_post payload ({} chars)", userJson.length)
            }
        }
        filterChain.doFilter(request, response)
    }
}
