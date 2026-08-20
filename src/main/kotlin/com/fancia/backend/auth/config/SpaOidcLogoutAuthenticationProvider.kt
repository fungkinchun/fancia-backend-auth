package com.fancia.backend.auth.config

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationContext
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationValidator
import org.springframework.util.CollectionUtils
import org.springframework.util.StringUtils
import java.time.Instant

class SpaOidcLogoutAuthenticationProvider(
    private val registeredClientRepository: RegisteredClientRepository,
    private val authorizationService: OAuth2AuthorizationService,
    private val jwtDecoder: JwtDecoder,
) : AuthenticationProvider {
    private val postLogoutValidator = OidcLogoutAuthenticationValidator()
    override fun authenticate(authentication: Authentication): Authentication {
        val logoutAuthentication = authentication as OidcLogoutAuthenticationToken
        val idTokenHint = logoutAuthentication.idTokenHint?.trim()?.takeIf(StringUtils::hasText)
            ?: throwLogoutError(OAuth2ErrorCodes.INVALID_TOKEN, "id_token_hint")
        val authorization = authorizationService.findByToken(idTokenHint, ID_TOKEN_TYPE)
        if (authorization != null) {
            return authenticateWithAuthorization(logoutAuthentication, authorization)
        }

        return authenticateWithJwtHint(logoutAuthentication, idTokenHint)
    }

    private fun authenticateWithAuthorization(
        logoutAuthentication: OidcLogoutAuthenticationToken,
        authorization: OAuth2Authorization,
    ): Authentication {
        val authorizedIdToken = authorization.getToken(OidcIdToken::class.java)
        if (authorizedIdToken == null || authorizedIdToken.isInvalidated) {
            throwLogoutError(OAuth2ErrorCodes.INVALID_TOKEN, "id_token_hint")
        }
        val registeredClient = registeredClientRepository.findById(authorization.registeredClientId)
            ?: throwLogoutError(OAuth2ErrorCodes.INVALID_CLIENT, OAuth2ParameterNames.CLIENT_ID)
        val idToken = authorizedIdToken.token
        validateClientAndAudience(logoutAuthentication, registeredClient, idToken.audience)
        val context = OidcLogoutAuthenticationContext.with(logoutAuthentication)
            .registeredClient(registeredClient)
            .build()
        postLogoutValidator.accept(context)

        return OidcLogoutAuthenticationToken(
            idToken,
            logoutAuthentication.principal as Authentication?,
            logoutAuthentication.sessionId,
            logoutAuthentication.clientId,
            logoutAuthentication.postLogoutRedirectUri,
            logoutAuthentication.state,
        )
    }

    private fun authenticateWithJwtHint(
        logoutAuthentication: OidcLogoutAuthenticationToken,
        idTokenHint: String,
    ): Authentication {
        val jwt = decodeIdTokenHint(idTokenHint)
        val registeredClient = resolveRegisteredClient(logoutAuthentication, jwt)
        validateClientAndAudience(logoutAuthentication, registeredClient, jwt.audience)
        val idToken = OidcIdToken(
            idTokenHint,
            jwt.issuedAt,
            jwt.expiresAt,
            jwt.claims,
        )
        val context = OidcLogoutAuthenticationContext.with(logoutAuthentication)
            .registeredClient(registeredClient)
            .build()
        postLogoutValidator.accept(context)

        return OidcLogoutAuthenticationToken(
            idToken,
            logoutAuthentication.principal as Authentication?,
            jwt.getClaimAsString("sid"),
            registeredClient.clientId,
            logoutAuthentication.postLogoutRedirectUri,
            logoutAuthentication.state,
        )
    }

    private fun decodeIdTokenHint(idTokenHint: String): Jwt {
        val jwt = try {
            jwtDecoder.decode(idTokenHint)
        } catch (_: Exception) {
            throwLogoutError(OAuth2ErrorCodes.INVALID_TOKEN, "id_token_hint")
        }

        if (jwt.expiresAt != null && jwt.expiresAt!!.isBefore(Instant.now())) {
            throwLogoutError(OAuth2ErrorCodes.INVALID_TOKEN, "id_token_hint")
        }

        return jwt
    }

    private fun resolveRegisteredClient(
        logoutAuthentication: OidcLogoutAuthenticationToken,
        jwt: Jwt,
    ): RegisteredClient {
        val clientId = when {
            StringUtils.hasText(logoutAuthentication.clientId) -> logoutAuthentication.clientId
            StringUtils.hasText(jwt.getClaimAsString("azp")) -> jwt.getClaimAsString("azp")
            !CollectionUtils.isEmpty(jwt.audience) -> jwt.audience.first()
            else -> throwLogoutError(OAuth2ErrorCodes.INVALID_CLIENT, OAuth2ParameterNames.CLIENT_ID)
        }

        return registeredClientRepository.findByClientId(clientId)
            ?: throwLogoutError(OAuth2ErrorCodes.INVALID_CLIENT, OAuth2ParameterNames.CLIENT_ID)
    }

    private fun validateClientAndAudience(
        logoutAuthentication: OidcLogoutAuthenticationToken,
        registeredClient: RegisteredClient,
        audience: List<String>,
    ) {
        if (CollectionUtils.isEmpty(audience) || !audience.contains(registeredClient.clientId)) {
            throwLogoutError(OAuth2ErrorCodes.INVALID_TOKEN, IdTokenClaimNames.AUD)
        }
        if (StringUtils.hasText(logoutAuthentication.clientId)
            && logoutAuthentication.clientId != registeredClient.clientId
        ) {
            throwLogoutError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID)
        }
    }

    override fun supports(authentication: Class<*>): Boolean =
        OidcLogoutAuthenticationToken::class.java.isAssignableFrom(authentication)

    private fun throwLogoutError(errorCode: String, parameterName: String): Nothing {
        throw OAuth2AuthenticationException(
            OAuth2Error(
                errorCode,
                "OpenID Connect 1.0 Logout Request Parameter: $parameterName",
                "https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling",
            )
        )
    }

    companion object {
        private val ID_TOKEN_TYPE = OAuth2TokenType(OidcParameterNames.ID_TOKEN)
    }
}
