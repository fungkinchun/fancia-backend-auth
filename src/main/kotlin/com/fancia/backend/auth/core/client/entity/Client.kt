package com.fancia.backend.auth.core.client.entity

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant

@Entity
@Table(name = "`clients`")
class Client(
    @Id var id: String? = null,
    @Column(unique = true) var clientId: String? = null,
    var clientIdIssuedAt: Instant? = null,
    var clientSecret: String? = null,
    var clientSecretExpiresAt: Instant? = null,
    var clientName: String? = null,
    @Column(length = 1000) var clientAuthenticationMethods: String? = null,
    @Column(length = 1000) var authorizationGrantTypes: String? = null,
    @Column(length = 1000) var redirectUris: String? = null,
    @Column(length = 1000) var postLogoutRedirectUris: String? = null,
    @Column(length = 1000) var scopes: String? = null,
    @Column(length = 2000) var clientSettings: String? = null,
    @Column(length = 2000) var tokenSettings: String? = null
)