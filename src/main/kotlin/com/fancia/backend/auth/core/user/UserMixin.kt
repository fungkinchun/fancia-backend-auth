package com.fancia.backend.auth.core.user

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import java.util.*

@JsonIgnoreProperties(
    ignoreUnknown = true, value = ["role", "verified", "authorities", "password", "enabled"]
)
abstract class UserMixin @JsonCreator constructor(
    @JsonProperty(value = "id") id: UUID,
    @JsonProperty("email") email: String,
    @JsonProperty("firstName") firstName: String,
    @JsonProperty("lastName") lastName: String,
    @JsonProperty("profileImageUrl") profileImageUrl: String
)