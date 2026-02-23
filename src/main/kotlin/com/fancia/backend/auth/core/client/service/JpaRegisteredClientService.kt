package com.fancia.backend.auth.core.client.service

import com.fancia.backend.auth.core.client.dto.CreateClientRequest
import com.fancia.backend.auth.core.client.repository.JpaRegisteredClientRepository
import jakarta.transaction.Transactional
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.stereotype.Service
import java.util.*

@Service
class JpaRegisteredClientService(
    private val registeredClientRepository: JpaRegisteredClientRepository
) {
    @Transactional
    fun create(request: CreateClientRequest) {
        val registeredClient = RegisteredClient.withId(UUID.randomUUID().toString()).clientId(request.clientId)
            .clientName(request.clientName).redirectUris { it.addAll(request.redirectUris) }
            .scopes { it.addAll(request.scopes) }.clientAuthenticationMethods { methods ->
                request.clientAuthenticationMethods.forEach { method ->
                    methods.add(ClientAuthenticationMethod(method))
                }
            }.authorizationGrantTypes { grantTypes ->
                request.authorizationGrantTypes.forEach { grantType ->
                    grantTypes.add(AuthorizationGrantType(grantType))
                }
            }.tokenSettings(
                TokenSettings.builder().accessTokenTimeToLive(
                    request.accessTokenTimeToLive
                ).refreshTokenTimeToLive(request.refreshTokenTimeToLive)
                    .authorizationCodeTimeToLive(request.authorizationCodeTimeToLive)
                    .deviceCodeTimeToLive(request.deviceCodeTimeToLive)
                    .reuseRefreshTokens(request.reuseRefreshTokens).build()
            ).build()
        registeredClientRepository.save(registeredClient)
    }

    fun findById(id: String): RegisteredClient? {
        return registeredClientRepository.findById(id)
    }

    fun findByClientId(clientId: String): RegisteredClient? {
        return registeredClientRepository.findByClientId(clientId)
    }
}