package com.fancia.backend.auth.security

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.web.filter.OncePerRequestFilter

class AppleSignInUserCaptureFilter : OncePerRequestFilter() {
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        if (request.method.equals("POST", ignoreCase = true)) {
            val userJson = request.getParameter("user")
            val code = request.getParameter("code")
            if (!userJson.isNullOrBlank() && !code.isNullOrBlank()) {
                request.getSession(true).setAttribute(AppleSignInUser.SESSION_ATTRIBUTE, userJson)
            }
        }
        filterChain.doFilter(request, response)
    }
}
