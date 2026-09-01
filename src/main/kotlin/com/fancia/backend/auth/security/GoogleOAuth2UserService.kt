package com.fancia.backend.auth.security

import com.fancia.backend.auth.core.user.repository.UserConnectedAccountRepository
import com.fancia.backend.auth.core.user.repository.UserRepository
import com.fancia.backend.shared.user.core.entity.User
import com.fancia.backend.shared.user.core.entity.UserConnectedAccount
import com.fancia.backend.shared.user.core.support.DefaultUserSlug
import com.fancia.backend.shared.user.core.enums.AccountStatus
import com.fancia.backend.shared.user.core.enums.ConnectedAccountProvider
import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class GoogleOAuth2UserService(
    private val userRepository: UserRepository,
    private val connectedAccountRepository: UserConnectedAccountRepository,
) : OidcUserService() {
    private val log = LoggerFactory.getLogger(javaClass)

    @Transactional
    override fun loadUser(userRequest: OidcUserRequest): OidcUser {
        val oidcUser = super.loadUser(userRequest)
        val registrationId = userRequest.clientRegistration.registrationId
        require(registrationId == "google") {
            "Unsupported OAuth2 registration: $registrationId"
        }
        val googleSub = oidcUser.name
        val email = oidcUser.getAttribute<String>("email")
            ?: throw OAuth2AuthenticationException("Google did not return an email address")
        val user = findOrCreateUser(googleSub, email, oidcUser)
        log.info("Google OAuth2 login provisioned user {}", user.email)
        return AppOidcUser.from(user, oidcUser)
    }

    private fun findOrCreateUser(googleSub: String, email: String, oauth2User: OAuth2User): User {
        connectedAccountRepository
            .findByProviderAndProviderIdWithUser(ConnectedAccountProvider.GOOGLE.value, googleSub)
            ?.user
            ?.let { return it }

        userRepository.findByEmail(email)?.let { existing ->
            linkGoogleAccount(existing, googleSub)
            applyInitialProfileFromGoogle(existing, oauth2User)
            assignDefaultSlugIfMissing(existing)
            return userRepository.save(existing)
        }
        val newUser = User(oauth2User).apply {
            applyInitialProfileFromGoogle(this, oauth2User)
            assignDefaultSlugIfMissing(this)
        }
        val savedUser = userRepository.save(newUser)
        linkGoogleAccount(savedUser, googleSub)
        log.info("Registered new user via Google OAuth2: {}", savedUser.email)
        return savedUser
    }

    private fun linkGoogleAccount(user: User, googleSub: String) {
        val alreadyLinked = connectedAccountRepository
            .findByProviderAndProviderIdWithUser(ConnectedAccountProvider.GOOGLE.value, googleSub) != null
        if (alreadyLinked) {
            return
        }
        connectedAccountRepository.save(
            UserConnectedAccount(ConnectedAccountProvider.GOOGLE.value, googleSub, user)
        )
    }

    private fun applyInitialProfileFromGoogle(user: User, oauth2User: OAuth2User) {
        oauth2User.getAttribute<String>("given_name")?.let { user.firstName = it }
        oauth2User.getAttribute<String>("family_name")?.let { user.lastName = it }

        if (user.firstName.isNullOrBlank()) {
            oauth2User.getAttribute<String>("name")?.let { fullName ->
                val parts = fullName.trim().split("\\s+".toRegex()).filter { it.isNotBlank() }
                if (parts.size > 1) {
                    user.firstName = parts.first()
                    user.lastName = parts.drop(1).joinToString(" ")
                } else if (parts.isNotEmpty()) {
                    user.firstName = parts.first()
                }
            }
        }
        user.status = AccountStatus.ACTIVE
    }

    private fun assignDefaultSlugIfMissing(user: User) {
        if (!user.slug.isNullOrBlank()) return
        user.slug = DefaultUserSlug.generate(user) { candidate ->
            userRepository.findBySlug(candidate) != null
        }
    }
}
