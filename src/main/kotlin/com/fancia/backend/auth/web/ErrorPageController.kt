package com.fancia.backend.auth.web

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.web.error.ErrorAttributeOptions
import org.springframework.boot.webmvc.autoconfigure.error.AbstractErrorController
import org.springframework.boot.webmvc.error.ErrorAttributes
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.RequestMapping

@Controller
@RequestMapping("\${spring.web.error.path:\${error.path:/error}}")
class ErrorPageController(
    errorAttributes: ErrorAttributes,
    @Value("\${DOMAIN_NAME}") private val domainName: String,
) : AbstractErrorController(errorAttributes) {
    @RequestMapping(produces = [MediaType.TEXT_HTML_VALUE])
    fun errorHtml(
        request: HttpServletRequest,
        response: HttpServletResponse,
        model: Model,
    ): String {
        response.status = getStatus(request).value()
        model.addAttribute("redirectUrl", "https://$domainName")
        model.addAttribute("redirectDelaySeconds", REDIRECT_DELAY_SECONDS)
        return "error"
    }

    @RequestMapping
    fun error(request: HttpServletRequest): ResponseEntity<Map<String, Any?>> {
        val status = getStatus(request)
        if (status == HttpStatus.NO_CONTENT) {
            return ResponseEntity(status)
        }
        val body = getErrorAttributes(request, ErrorAttributeOptions.defaults())
        return ResponseEntity(body, status)
    }

    companion object {
        private const val REDIRECT_DELAY_SECONDS = 8
    }
}
