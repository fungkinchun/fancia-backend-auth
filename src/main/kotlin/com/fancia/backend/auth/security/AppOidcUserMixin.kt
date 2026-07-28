package com.fancia.backend.auth.security

import com.fancia.backend.shared.user.core.entity.User
import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcUserInfo

@JsonIgnoreProperties(ignoreUnknown = true)
abstract class AppOidcUserMixin @JsonCreator constructor(
    @JsonProperty("user") user: User,
    @JsonProperty("attributes") attributes: Map<String, Any>,
    @JsonProperty("idToken") idToken: OidcIdToken,
    @JsonProperty("userInfo") userInfo: OidcUserInfo?,
)
