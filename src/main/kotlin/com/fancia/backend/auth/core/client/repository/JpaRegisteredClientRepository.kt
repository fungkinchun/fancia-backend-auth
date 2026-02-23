package com.fancia.backend.auth.core.client.repository

import com.fancia.backend.auth.core.client.entity.Client
import com.fancia.backend.auth.core.user.TokenSettingsMixin
import org.springframework.security.jackson.SecurityJacksonModules
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.jackson.OAuth2AuthorizationServerJacksonModule
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.stereotype.Repository
import org.springframework.util.StringUtils
import tools.jackson.core.type.TypeReference
import tools.jackson.databind.JacksonModule
import tools.jackson.databind.json.JsonMapper
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator

@Repository
class JpaRegisteredClientRepository(
    private val clientRepository: ClientRepository
) : RegisteredClientRepository {
    private val objectMapper = JsonMapper.builder().apply {
        val typeValidator =
            BasicPolymorphicTypeValidator.builder().allowIfSubType("com.fancia.backend.").allowIfSubType(
                SignatureAlgorithm::class.java
            )
        val classLoader = JpaRegisteredClientRepository::class.java.classLoader
        val securityModules: List<JacksonModule> = SecurityJacksonModules.getModules(classLoader, typeValidator)
        addModules(securityModules)
        addModules(OAuth2AuthorizationServerJacksonModule())
        val addMixIn = addMixIn(TokenSettings::class.java, TokenSettingsMixin::class.java)
    }.build()

    override fun save(registeredClient: RegisteredClient) {
        requireNotNull(registeredClient) { "registeredClient cannot be null" }
        clientRepository.save(toEntity(registeredClient))
    }

    override fun findById(id: String): RegisteredClient? {
        require(id.isNotBlank()) { "id cannot be empty" }
        val client = clientRepository.findById(id).map { toObject(it) }.orElse(null)
        return client
    }

    override fun findByClientId(clientId: String): RegisteredClient? {
        require(clientId.isNotBlank()) { "clientId cannot be empty" }
        return clientRepository.findByClientId(clientId)?.let { toObject(it) }
    }

    private fun toObject(client: Client): RegisteredClient {
        val clientAuthenticationMethods = StringUtils.commaDelimitedListToSet(client.clientAuthenticationMethods)
        val authorizationGrantTypes = StringUtils.commaDelimitedListToSet(client.authorizationGrantTypes)
        val redirectUris = StringUtils.commaDelimitedListToSet(client.redirectUris)
        val postLogoutRedirectUris = StringUtils.commaDelimitedListToSet(client.postLogoutRedirectUris)
        val clientScopes = StringUtils.commaDelimitedListToSet(client.scopes)
        val builder = RegisteredClient.withId(client.id.toString()).clientId(client.clientId)
            .clientIdIssuedAt(client.clientIdIssuedAt).clientSecret(client.clientSecret)
            .clientSecretExpiresAt(client.clientSecretExpiresAt).clientName(client.clientName)
            .clientAuthenticationMethods { methods ->
                clientAuthenticationMethods.forEach { methods.add(resolveClientAuthenticationMethod(it)) }
            }.authorizationGrantTypes { grantTypes ->
                authorizationGrantTypes.forEach { grantTypes.add(resolveAuthorizationGrantType(it)) }
            }.redirectUris { it.addAll(redirectUris) }.postLogoutRedirectUris { it.addAll(postLogoutRedirectUris) }
            .scopes { it.addAll(clientScopes) }
        val clientSettingsMap = parseMap(client.clientSettings)
        clientSettingsMap.takeIf { it.isNotEmpty() }
            ?.let { builder.clientSettings(ClientSettings.withSettings(it).build()) }
        val tokenSettingsMap = parseMap(client.tokenSettings)
        tokenSettingsMap.takeIf { it.isNotEmpty() }?.let {
            builder.tokenSettings(TokenSettings.withSettings(it).build())
        }
        return builder.build()
    }

    private fun toEntity(registeredClient: RegisteredClient): Client {
        val entity = Client()
        entity.id = registeredClient.id
        entity.clientId = registeredClient.clientId
        entity.clientIdIssuedAt = registeredClient.clientIdIssuedAt
        entity.clientSecret = registeredClient.clientSecret
        entity.clientSecretExpiresAt = registeredClient.clientSecretExpiresAt
        entity.clientName = registeredClient.clientName

        entity.clientAuthenticationMethods =
            StringUtils.collectionToCommaDelimitedString(registeredClient.clientAuthenticationMethods)

        entity.authorizationGrantTypes =
            StringUtils.collectionToCommaDelimitedString(registeredClient.authorizationGrantTypes.map { it.value.toString() })

        entity.redirectUris =
            StringUtils.collectionToCommaDelimitedString(registeredClient.redirectUris)

        entity.postLogoutRedirectUris =
            StringUtils.collectionToCommaDelimitedString(registeredClient.postLogoutRedirectUris)

        entity.scopes =
            StringUtils.collectionToCommaDelimitedString(registeredClient.scopes)

        entity.clientSettings =
            writeMap(registeredClient.clientSettings.settings)

        entity.tokenSettings =
            writeMap(registeredClient.tokenSettings.settings)
        return entity
    }

    private fun parseMap(data: String?): Map<String, Any> {
        return try {
            objectMapper.readValue(data, object : TypeReference<Map<String, Any>>() {})
        } catch (ex: Exception) {
            throw IllegalArgumentException(ex.message, ex)
        }
    }

    private fun writeMap(data: Map<String, Any>): String {
        return try {
            objectMapper.writeValueAsString(data)
        } catch (ex: Exception) {
            throw java.lang.IllegalArgumentException(ex.message, ex)
        }
    }

    companion object {
        private fun resolveAuthorizationGrantType(authorizationGrantType: String): AuthorizationGrantType {
            return when (authorizationGrantType) {
                AuthorizationGrantType.AUTHORIZATION_CODE.value -> AuthorizationGrantType.AUTHORIZATION_CODE
                AuthorizationGrantType.CLIENT_CREDENTIALS.value -> AuthorizationGrantType.CLIENT_CREDENTIALS
                AuthorizationGrantType.REFRESH_TOKEN.value -> AuthorizationGrantType.REFRESH_TOKEN
                else -> AuthorizationGrantType(authorizationGrantType)
            }
        }

        private fun resolveClientAuthenticationMethod(clientAuthenticationMethod: String): ClientAuthenticationMethod {
            return when (clientAuthenticationMethod) {
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value -> ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                ClientAuthenticationMethod.CLIENT_SECRET_POST.value -> ClientAuthenticationMethod.CLIENT_SECRET_POST
                ClientAuthenticationMethod.NONE.value -> ClientAuthenticationMethod.NONE
                else -> ClientAuthenticationMethod(clientAuthenticationMethod)
            }
        }
    }
}