package com.fancia.backend.auth.core.client.repository

import com.fancia.backend.auth.core.client.entity.AuthorizationConsent
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface AuthorizationConsentRepository :
    JpaRepository<AuthorizationConsent, AuthorizationConsent.AuthorizationConsentId> {
    fun findByRegisteredClientIdAndPrincipalName(
        registeredClientId: String, principalName: String
    ): AuthorizationConsent?

    fun deleteByRegisteredClientIdAndPrincipalName(
        registeredClientId: String, principalName: String
    )
}