package com.fancia.backend.auth.config

import com.fancia.backend.auth.core.client.dto.CreateClientRequest
import com.fancia.backend.auth.core.client.service.JpaRegisteredClientService
import org.springframework.boot.ApplicationRunner
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class DataInitializer(
    private val oauthServerProperties: OAuth2AuthorizationServerProperties,
) {
    @Bean
    fun initClients(clientService: JpaRegisteredClientService) = ApplicationRunner {
        oauthServerProperties.client.forEach { (name, client) ->
            client.registration.takeIf {
                it.clientId != null && clientService.findByClientId(
                    client.registration.clientId!!
                ) == null
            }?.let { registration ->
                val request = CreateClientRequest(
                    clientId = client.registration.clientId,
                    clientName = name,
                    redirectUris = client.registration.redirectUris.toSet(),
                    scopes = client.registration.scopes.toSet(),
                    clientAuthenticationMethods = client.registration.clientAuthenticationMethods.toSet(),
                    authorizationGrantTypes = client.registration.authorizationGrantTypes.toSet(),
                    accessTokenTimeToLive = client.token.accessTokenTimeToLive,
                    refreshTokenTimeToLive = client.token.refreshTokenTimeToLive,
                    authorizationCodeTimeToLive = client.token.authorizationCodeTimeToLive,
                    deviceCodeTimeToLive = client.token.deviceCodeTimeToLive,
                    reuseRefreshTokens = client.token.isReuseRefreshTokens
                )
                clientService.create(request)
            }
        }
    }
}