package com.fancia.backend.auth.security

import com.fancia.backend.shared.user.core.entity.User
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.core.oidc.user.OidcUser

class AppOidcUser(
    val user: User,
    private val attributes: Map<String, Any>,
    private val idToken: OidcIdToken,
    private val userInfo: OidcUserInfo? = null,
) : OidcUser {
    override fun getAttributes(): Map<String, Any> = attributes
    override fun getAuthorities(): Collection<GrantedAuthority> = user.authorities
    override fun getName(): String = user.username
    override fun getClaims(): Map<String, Any> = idToken.claims
    override fun getIdToken(): OidcIdToken = idToken
    override fun getUserInfo(): OidcUserInfo? = userInfo

    companion object {
        fun from(user: User, oidcUser: OidcUser): AppOidcUser =
            AppOidcUser(user, oidcUser.attributes, oidcUser.idToken, oidcUser.userInfo)
    }
}
