package com.fancia.backend.auth.core.client.service

import com.fancia.backend.auth.core.client.entity.Authorization
import com.fancia.backend.auth.core.client.repository.AuthorizationRepository
import com.fancia.backend.auth.core.client.repository.ClientRepository
import com.fancia.backend.auth.core.user.UserMixin
import com.fancia.backend.shared.user.core.entity.User
import org.springframework.dao.DataRetrievalFailureException
import org.springframework.security.jackson.SecurityJacksonModules
import org.springframework.security.oauth2.core.*
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.jackson.OAuth2AuthorizationServerJacksonModule
import org.springframework.stereotype.Component
import org.springframework.util.StringUtils
import tools.jackson.core.type.TypeReference
import tools.jackson.databind.JacksonModule
import tools.jackson.databind.json.JsonMapper
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator
import java.time.Instant

@Component
class JpaOAuth2AuthorizationService(
    private val authorizationRepository: AuthorizationRepository,
    private val registeredClientRepository: RegisteredClientRepository,
    private val clientRepository: ClientRepository
) : OAuth2AuthorizationService {
    private val objectMapper = JsonMapper.builder().apply {
        val classLoader = JpaOAuth2AuthorizationService::class.java.classLoader
        val typeValidator = BasicPolymorphicTypeValidator.builder().allowIfSubType("com.fancia.backend.")
        val securityModules: List<JacksonModule> = SecurityJacksonModules.getModules(classLoader, typeValidator)
        addModules(securityModules)
        addModules(OAuth2AuthorizationServerJacksonModule())
        val addMixIn = addMixIn(User::class.java, UserMixin::class.java)
    }.build()

    override fun save(authorization: OAuth2Authorization) {
        requireNotNull(authorization) { "authorization cannot be null" }
        authorizationRepository.save(toEntity(authorization))
    }

    override fun remove(authorization: OAuth2Authorization) {
        requireNotNull(authorization) { "authorization cannot be null" }
        authorizationRepository.deleteById(authorization.id)
    }

    override fun findById(id: String): OAuth2Authorization? {
        require(id.isNotBlank()) { "id cannot be empty" }
        return authorizationRepository.findById(id).map { toObject(it) }.orElse(null)
    }

    override fun findByToken(token: String, tokenType: OAuth2TokenType?): OAuth2Authorization? {
        require(token.isNotBlank()) { "token cannot be empty" }
        val result = when (tokenType?.value) {
            null -> authorizationRepository.findByAnyToken(token)
            OAuth2ParameterNames.STATE -> authorizationRepository.findByState(token)
            OAuth2ParameterNames.CODE -> authorizationRepository.findByAuthorizationCodeValue(token)
            OAuth2ParameterNames.ACCESS_TOKEN -> authorizationRepository.findByAccessTokenValue(token)
            OAuth2ParameterNames.REFRESH_TOKEN -> authorizationRepository.findByRefreshTokenValue(token)
            OidcParameterNames.ID_TOKEN -> authorizationRepository.findByOidcIdTokenValue(token)
            OAuth2ParameterNames.USER_CODE -> authorizationRepository.findByUserCodeValue(token)
            OAuth2ParameterNames.DEVICE_CODE -> authorizationRepository.findByDeviceCodeValue(token)
            else -> null
        }
        return result?.let { if (it != null) toObject(it) else null }
    }

    private fun toObject(entity: Authorization): OAuth2Authorization {
        val registeredClient =
            registeredClientRepository.findById(entity.client?.id) ?: throw DataRetrievalFailureException(
                "The RegisteredClient with id '${entity.id}' was not found in the RegisteredClientRepository."
            )
        val builder = OAuth2Authorization.withRegisteredClient(registeredClient).principalName(entity.principalName)
            .authorizationGrantType(resolveAuthorizationGrantType(entity.authorizationGrantType))
            .authorizedScopes(StringUtils.commaDelimitedListToSet(entity.authorizedScopes))
            .attributes { it.putAll(parseMap(entity.attributes)) }

        entity.state?.let { builder.attribute(OAuth2ParameterNames.STATE, it) }

        entity.authorizationCodeValue?.let {
            val code = OAuth2AuthorizationCode(
                it, entity.authorizationCodeIssuedAt, entity.authorizationCodeExpiresAt
            )
            builder.token(code) { meta -> meta.putAll(parseMap(entity.authorizationCodeMetadata)) }
        }

        entity.accessTokenValue?.let {
            val accessToken = OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                it,
                entity.accessTokenIssuedAt,
                entity.accessTokenExpiresAt,
                StringUtils.commaDelimitedListToSet(entity.accessTokenScopes)
            )
            builder.token(accessToken) { meta -> meta.putAll(parseMap(entity.accessTokenMetadata)) }
        }

        entity.refreshTokenValue?.let {
            val refreshToken = OAuth2RefreshToken(
                it, entity.refreshTokenIssuedAt, entity.refreshTokenExpiresAt
            )
            builder.token(refreshToken) { meta -> meta.putAll(parseMap(entity.refreshTokenMetadata)) }
        }

        entity.oidcIdTokenValue?.let {
            val idToken = OidcIdToken(
                it, entity.oidcIdTokenIssuedAt, entity.oidcIdTokenExpiresAt, parseMap(entity.oidcIdTokenClaims)
            )
            builder.token(idToken) { meta -> meta.putAll(parseMap(entity.oidcIdTokenMetadata)) }
        }

        entity.userCodeValue?.let {
            val userCode = OAuth2UserCode(
                it, entity.userCodeIssuedAt, entity.userCodeExpiresAt
            )
            builder.token(userCode) { meta -> meta.putAll(parseMap(entity.userCodeMetadata)) }
        }

        entity.deviceCodeValue?.let {
            val deviceCode = OAuth2DeviceCode(
                it, entity.deviceCodeIssuedAt, entity.deviceCodeExpiresAt
            )
            builder.token(deviceCode) { meta -> meta.putAll(parseMap(entity.deviceCodeMetadata)) }
        }

        return builder.build()
    }

    private fun toEntity(authorization: OAuth2Authorization): Authorization {
        val entity = Authorization()
        entity.id = authorization.id ?: throw IllegalArgumentException("Authorization ID cannot be null")
        val client = clientRepository.findById(authorization.registeredClientId)
            .orElseThrow {
                DataRetrievalFailureException(
                    "The RegisteredClient with id '${authorization.registeredClientId}' was not found in the RegisteredClientRepository."
                )
            }
        entity.client = client

        entity.principalName = authorization.principalName
        entity.authorizationGrantType = authorization.authorizationGrantType.value
        entity.authorizedScopes = StringUtils.collectionToDelimitedString(authorization.authorizedScopes, ",")
        entity.attributes = writeMap(authorization.attributes)
        entity.state = authorization.getAttribute(OAuth2ParameterNames.STATE)

        setTokenValues(
            authorization.getToken(OAuth2AuthorizationCode::class.java),
            { entity.authorizationCodeValue = it },
            { entity.authorizationCodeIssuedAt = it },
            { entity.authorizationCodeExpiresAt = it },
            { entity.authorizationCodeMetadata = it })
        val accessToken = authorization.getToken(OAuth2AccessToken::class.java)
        setTokenValues(
            accessToken,
            { entity.accessTokenValue = it },
            { entity.accessTokenIssuedAt = it },
            { entity.accessTokenExpiresAt = it },
            { entity.accessTokenMetadata = it })
        if (accessToken?.token?.scopes != null) {
            entity.accessTokenScopes = StringUtils.collectionToDelimitedString(accessToken.token.scopes, ",")
        }

        setTokenValues(
            authorization.getToken(OAuth2RefreshToken::class.java),
            { entity.refreshTokenValue = it },
            { entity.refreshTokenIssuedAt = it },
            { entity.refreshTokenExpiresAt = it },
            { entity.refreshTokenMetadata = it })
        val oidcIdToken = authorization.getToken(OidcIdToken::class.java)
        setTokenValues(
            oidcIdToken,
            { entity.oidcIdTokenValue = it },
            { entity.oidcIdTokenIssuedAt = it },
            { entity.oidcIdTokenExpiresAt = it },
            { entity.oidcIdTokenMetadata = it })
        if (oidcIdToken != null) {
            entity.oidcIdTokenClaims = writeMap(oidcIdToken.claims)
        }

        setTokenValues(
            authorization.getToken(OAuth2UserCode::class.java),
            { entity.userCodeValue = it },
            { entity.userCodeIssuedAt = it },
            { entity.userCodeExpiresAt = it },
            { entity.userCodeMetadata = it })

        setTokenValues(
            authorization.getToken(OAuth2DeviceCode::class.java),
            { entity.deviceCodeValue = it },
            { entity.deviceCodeIssuedAt = it },
            { entity.deviceCodeExpiresAt = it },
            { entity.deviceCodeMetadata = it })

        return entity
    }

    private fun setTokenValues(
        token: OAuth2Authorization.Token<out OAuth2Token>?,
        tokenValueConsumer: (String?) -> Unit,
        issuedAtConsumer: (Instant?) -> Unit,
        expiresAtConsumer: (Instant?) -> Unit,
        metadataConsumer: (String?) -> Unit
    ) {
        if (token != null) {
            val oAuth2Token = token.token
            tokenValueConsumer(oAuth2Token.tokenValue)
            issuedAtConsumer(oAuth2Token.issuedAt)
            expiresAtConsumer(oAuth2Token.expiresAt)
            metadataConsumer(writeMap(token.metadata))
        }
    }

    private fun parseMap(data: String?): Map<String, Any> {
        return try {
            objectMapper.readValue(data, object : TypeReference<Map<String, Any>>() {})
        } catch (ex: Exception) {
            throw IllegalArgumentException(ex.message, ex)
        }
    }

    private fun writeMap(metadata: Map<String, Any>?): String {
        return try {
            objectMapper.writeValueAsString(metadata ?: emptyMap<String, Any>())
        } catch (ex: Exception) {
            throw IllegalArgumentException(ex.message, ex)
        }
    }

    companion object {
        private fun resolveAuthorizationGrantType(authorizationGrantType: String?): AuthorizationGrantType {
            return when (authorizationGrantType) {
                AuthorizationGrantType.AUTHORIZATION_CODE.value -> AuthorizationGrantType.AUTHORIZATION_CODE
                AuthorizationGrantType.CLIENT_CREDENTIALS.value -> AuthorizationGrantType.CLIENT_CREDENTIALS
                AuthorizationGrantType.REFRESH_TOKEN.value -> AuthorizationGrantType.REFRESH_TOKEN
                AuthorizationGrantType.DEVICE_CODE.value -> AuthorizationGrantType.DEVICE_CODE
                else -> AuthorizationGrantType(authorizationGrantType)
            }
        }
    }
}