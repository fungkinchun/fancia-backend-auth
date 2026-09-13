package com.fancia.backend.auth.core.user

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import java.util.*

@JsonIgnoreProperties(
    ignoreUnknown = true,
    value = [
        "role",
        "status",
        "authorities",
        "password",
        "enabled",
        "links",
        "connectedAccounts",
        "tags",
        "settings",
        "accountNonExpired",
        "accountNonLocked",
        "credentialsNonExpired",
        "username",
        "premiumExpiresAt",
        "bio",
        "locationLabel",
        "birthDate",
        "gender",
        "visibility",
        "slug",
        "slugChangedAt",
        "createdBy",
        "createdAt",
    ],
)
abstract class UserMixin @JsonCreator constructor(
    @JsonProperty("id") id: UUID?,
    @JsonProperty("email") email: String?,
    @JsonProperty("firstName") firstName: String?,
    @JsonProperty("lastName") lastName: String?,
    @JsonProperty("profileImageUrl") profileImageUrl: String?,
    @JsonProperty("premiumActive") premiumActive: Boolean = false,
)
