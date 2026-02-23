package com.fancia.backend.auth.core.client.service

import com.fancia.backend.auth.core.client.entity.AuthorizationConsent
import com.fancia.backend.auth.core.client.repository.AuthorizationConsentRepository
import org.springframework.dao.DataRetrievalFailureException
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.stereotype.Component
import org.springframework.util.StringUtils

@Component
class JpaOAuth2AuthorizationConsentService(
    private val authorizationConsentRepository: AuthorizationConsentRepository,
    private val registeredClientRepository: RegisteredClientRepository
) : OAuth2AuthorizationConsentService {
    override fun save(authorizationConsent: OAuth2AuthorizationConsent) {
        requireNotNull(authorizationConsent) { "authorizationConsent cannot be null" }
        authorizationConsentRepository.save(toEntity(authorizationConsent))
    }

    override fun remove(authorizationConsent: OAuth2AuthorizationConsent) {
        requireNotNull(authorizationConsent) { "authorizationConsent cannot be null" }
        authorizationConsentRepository.deleteByRegisteredClientIdAndPrincipalName(
            authorizationConsent.registeredClientId, authorizationConsent.principalName
        )
    }

    override fun findById(registeredClientId: String, principalName: String): OAuth2AuthorizationConsent? {
        require(registeredClientId.isNotBlank()) { "registeredClientId cannot be empty" }
        require(principalName.isNotBlank()) { "principalName cannot be empty" }
        return authorizationConsentRepository.findByRegisteredClientIdAndPrincipalName(
            registeredClientId,
            principalName
        )?.let { toObject(it) }
    }

    private fun toObject(authorizationConsent: AuthorizationConsent): OAuth2AuthorizationConsent {
        val registeredClientId = authorizationConsent.registeredClientId
        registeredClientRepository.findById(registeredClientId) ?: throw DataRetrievalFailureException(
            "The RegisteredClient with id '$registeredClientId' was not found in the RegisteredClientRepository."
        )
        val builder = OAuth2AuthorizationConsent.withId(
            registeredClientId, authorizationConsent.principalName
        )
        authorizationConsent.authorities?.let {
            StringUtils.commaDelimitedListToSet(it).forEach { authority ->
                builder.authority(SimpleGrantedAuthority(authority))
            }
        }
        return builder.build()
    }

    private fun toEntity(authorizationConsent: OAuth2AuthorizationConsent): AuthorizationConsent {
        val authorities = authorizationConsent.authorities.map { it.authority }.toSet()
        val entity = AuthorizationConsent(
            registeredClientId = authorizationConsent.registeredClientId,
            principalName = authorizationConsent.principalName,
            authorities = StringUtils.collectionToCommaDelimitedString(authorities)
        )
        return entity
    }
}