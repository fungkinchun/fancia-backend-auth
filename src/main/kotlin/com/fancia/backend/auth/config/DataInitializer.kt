package com.fancia.backend.auth.config

import com.fancia.backend.auth.core.client.service.JpaRegisteredClientService
import com.fancia.backend.shared.auth.core.client.dto.CreateClientRequest
import org.slf4j.LoggerFactory
import org.springframework.boot.context.event.ApplicationReadyEvent
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerProperties
import org.springframework.context.annotation.Configuration
import org.springframework.context.event.EventListener
import java.util.concurrent.atomic.AtomicBoolean

@Configuration
class DataInitializer(
    private val oauthServerProperties: OAuth2AuthorizationServerProperties,
    private val clientService: JpaRegisteredClientService,
) {
    private val log = LoggerFactory.getLogger(javaClass)
    private val initialized = AtomicBoolean(false)

    @EventListener(ApplicationReadyEvent::class)
    fun onApplicationReady() {
        if (!initialized.compareAndSet(false, true)) {
            log.debug("OAuth client initialization already completed, skipping")
            return
        }
        log.info("Initializing OAuth clients after application is ready")
        initClients()
    }

    private fun initClients() {
        oauthServerProperties.client.forEach { (name, client) ->
            client.registration.takeIf {
                it.clientId != null && clientService.findByClientId(
                    client.registration.clientId!!
                ) == null
            }?.let {
                val request = CreateClientRequest(
                    clientId = client.registration.clientId,
                    clientName = name,
                    redirectUris = client.registration.redirectUris.toSet(),
                    postLogoutRedirectUris = client.registration.postLogoutRedirectUris.toSet(),
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
