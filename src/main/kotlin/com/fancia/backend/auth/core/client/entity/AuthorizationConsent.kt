package com.fancia.backend.auth.core.client.entity

import jakarta.persistence.*
import java.io.Serializable

@Entity
@Table(name = "`authorization_consents`")
@IdClass(AuthorizationConsent.AuthorizationConsentId::class)
data class AuthorizationConsent(
    @ManyToOne var client: Client? = null,
    @Id var registeredClientId: String,
    @Id var principalName: String,
    @Column(length = 1000) var authorities: String
) {
    data class AuthorizationConsentId(
        var registeredClientId: String, var principalName: String
    ) : Serializable
}