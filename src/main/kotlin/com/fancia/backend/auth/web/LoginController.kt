package com.fancia.backend.auth.web

import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import java.time.Year

@Controller
class LoginController(
    @Value("\${DOMAIN_NAME}") private val domainName: String,
) {
    @GetMapping("/login")
    fun login(model: Model): String {
        val siteUrl = "https://$domainName"
        model.addAttribute("domainName", siteUrl)
        model.addAttribute("signupUrl", "$siteUrl/signup")
        model.addAttribute("currentYear", Year.now().value)
        return "login"
    }
}
