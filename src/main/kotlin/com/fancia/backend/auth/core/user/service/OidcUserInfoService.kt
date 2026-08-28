package com.fancia.backend.auth.core.user.service

import com.fancia.backend.shared.user.core.entity.User
import com.fancia.backend.shared.user.core.enums.AccountStatus
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.stereotype.Service

@Service
class OidcUserInfoService(private val userDetailsService: UserDetailsService) {
    fun loadUser(username: String): OidcUserInfo {
        val user: User = userDetailsService.loadUserByUsername(username) as User
        return OidcUserInfo.builder()
            .subject(user.username)
            .name(user.firstName + " " + user.lastName)
            .preferredUsername(username)
            .email(user.email)
            .emailVerified(user.status == AccountStatus.ACTIVE)
            .picture(user.profileImageUrl)
            .claim("roles", user.role)
            .claim("isPremium", user.premiumActive)
            .build()
    }
}