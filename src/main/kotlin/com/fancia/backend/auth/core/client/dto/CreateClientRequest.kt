package com.fancia.backend.auth.core.client.dto

import com.fancia.backend.shared.common.core.validator.Unique
import java.time.Duration

data class CreateClientRequest(
    @Unique(
        columnName = "client_id", tableName = "clients", message = "Client with this clientId already exists"
    ) val clientId: String?,
    val clientName: String?,
    val redirectUris: Set<String>,
    val scopes: Set<String>,
    val clientAuthenticationMethods: Set<String>,
    val authorizationGrantTypes: Set<String>,
    val accessTokenTimeToLive: Duration,
    val refreshTokenTimeToLive: Duration,
    val authorizationCodeTimeToLive: Duration,
    val deviceCodeTimeToLive: Duration,
    val reuseRefreshTokens: Boolean
)