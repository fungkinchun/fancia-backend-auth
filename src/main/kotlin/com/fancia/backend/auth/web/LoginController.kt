package com.fancia.backend.auth.web

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import java.time.Year

@Controller
class LoginController(
    @Value("\${DOMAIN_NAME}") private val domainName: String,
) {
    private val requestCache = HttpSessionRequestCache()

    @GetMapping("/login")
    fun login(request: HttpServletRequest, response: HttpServletResponse, model: Model): String {
        val siteUrl = "https://$domainName"
        model.addAttribute("domainName", siteUrl)
        model.addAttribute("signupUrl", "$siteUrl/signup")
        model.addAttribute("currentYear", Year.now().value)
        model.addAttribute("theme", resolveTheme(request, response))
        return "login"
    }

    private fun resolveTheme(request: HttpServletRequest, response: HttpServletResponse): String {
        val requested = request.getParameter(THEME_PARAM)
            ?: requestCache.getRequest(request, response)
                ?.getParameterValues(THEME_PARAM)
                ?.firstOrNull()
        return requested?.takeIf { it in SUPPORTED_THEMES } ?: DEFAULT_THEME
    }

    private companion object {
        const val THEME_PARAM = "theme"
        const val DEFAULT_THEME = "system"
        val SUPPORTED_THEMES = setOf("light", "dark", DEFAULT_THEME)
    }
}
