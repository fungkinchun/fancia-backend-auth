package com.fancia.backend.auth.security

import jakarta.servlet.http.HttpServletRequest
import org.slf4j.LoggerFactory
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes
import tools.jackson.databind.json.JsonMapper

object AppleSignInUser {
    const val REQUEST_ATTRIBUTE = "APPLE_SIGN_IN_USER_JSON"

    private val log = LoggerFactory.getLogger(javaClass)
    private val jsonMapper = JsonMapper.builder().build()

    data class Name(val firstName: String?, val lastName: String?)

    fun consumeNameFromCurrentRequest(): Name? {
        val request = currentRequest() ?: return null
        val raw =
            (request.getAttribute(REQUEST_ATTRIBUTE) as? String)?.takeIf { it.isNotBlank() }
                ?: request.getParameter("user")?.takeIf { it.isNotBlank() }
                ?: return null
        request.removeAttribute(REQUEST_ATTRIBUTE)
        val name = parseName(raw)
        if (name == null) {
            log.info("Apple Sign In user payload present but contained no usable name")
        }
        return name
    }

    fun parseName(userJson: String): Name? =
        try {
            val root = jsonMapper.readTree(userJson)
            val nameNode = root.get("name") ?: return null
            if (nameNode.isValueNode) {
                val parts =
                    nameNode.asString()
                        .trim()
                        .split("\\s+".toRegex())
                        .filter { it.isNotBlank() }
                return when {
                    parts.isEmpty() -> null
                    parts.size == 1 -> Name(parts.first(), null)
                    else -> Name(parts.first(), parts.drop(1).joinToString(" "))
                }
            }
            val first = nameNode.get("firstName")?.asString()?.trim()?.takeIf { it.isNotEmpty() }
            val last = nameNode.get("lastName")?.asString()?.trim()?.takeIf { it.isNotEmpty() }
            if (first == null && last == null) null else Name(first, last)
        } catch (ex: Exception) {
            log.warn("Failed to parse Apple Sign In user payload: {}", ex.message)
            null
        }

    private fun currentRequest(): HttpServletRequest? {
        val attrs = RequestContextHolder.getRequestAttributes() as? ServletRequestAttributes
        return attrs?.request
    }
}
