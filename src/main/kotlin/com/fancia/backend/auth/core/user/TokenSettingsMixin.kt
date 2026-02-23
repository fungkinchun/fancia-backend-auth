package com.fancia.backend.auth.core.user

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import java.time.Duration

@JsonIgnoreProperties(
    ignoreUnknown = true,
    value = ["settings"]
)
abstract class TokenSettingsMixin {
    @JsonCreator
    constructor(
        @JsonProperty("accessTokenTimeToLive") accessTokenTimeToLive: Duration? = null,
        @JsonProperty("refreshTokenTimeToLive") refreshTokenTimeToLive: Duration? = null,
        @JsonProperty("authorizationCodeTimeToLive") authorizationCodeTimeToLive: Duration? = null,
        @JsonProperty("deviceCodeTimeToLive") deviceCodeTimeToLive: Duration? = null,
        @JsonProperty("idTokenSignatureAlgorithm") idTokenSignatureAlgorithm: SignatureAlgorithm? = null,
        @JsonProperty("accessTokenFormat") accessTokenFormat: OAuth2TokenFormat? = null,
        @JsonProperty("reuseRefreshTokens") reuseRefreshTokens: Boolean? = null,
        @JsonProperty("x509CertificateBoundAccessTokens") x509CertificateBoundAccessTokens: Boolean? = null
    )
}