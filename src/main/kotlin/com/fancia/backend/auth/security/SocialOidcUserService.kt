package com.fancia.backend.auth.security

import com.fancia.backend.auth.core.user.repository.UserConnectedAccountRepository
import com.fancia.backend.shared.user.core.repository.UserRepository
import com.fancia.backend.shared.user.core.entity.User
import com.fancia.backend.shared.user.core.entity.UserConnectedAccount
import com.fancia.backend.shared.user.core.enums.AccountStatus
import com.fancia.backend.shared.user.core.enums.ConnectedAccountProvider
import com.fancia.backend.shared.user.core.support.DefaultUserSlug
import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class SocialOidcUserService(
    private val userRepository: UserRepository,
    private val connectedAccountRepository: UserConnectedAccountRepository,
) : OidcUserService() {
    private val log = LoggerFactory.getLogger(javaClass)

    init {
        setRetrieveUserInfo { userRequest ->
            userRequest.clientRegistration.registrationId != "apple"
        }
    }

    @Transactional
    override fun loadUser(userRequest: OidcUserRequest): OidcUser {
        val oidcUser = super.loadUser(userRequest)
        val registrationId = userRequest.clientRegistration.registrationId
        val provider = providerFor(registrationId)
        val providerSubject = oidcUser.subject ?: oidcUser.name
        val email = oidcUser.getAttribute<String>("email")
            ?: oidcUser.idToken.getClaimAsString("email")
        val user = findOrCreateUser(registrationId, provider, providerSubject, email, oidcUser)
        log.info("{} OAuth2 login provisioned user {}", registrationId, user.email)
        return oidcUser
    }

    private fun providerFor(registrationId: String): String =
        when (registrationId) {
            "google" -> ConnectedAccountProvider.GOOGLE.value
            "apple" -> "apple" 
            else -> throw OAuth2AuthenticationException("Unsupported OAuth2 registration: $registrationId")
        }

    private fun findOrCreateUser(
        registrationId: String,
        provider: String,
        providerSubject: String,
        email: String?,
        oauth2User: OAuth2User,
    ): User {
        connectedAccountRepository
            .findByProviderAndProviderIdWithUser(provider, providerSubject)
            ?.user
            ?.let {
                if (registrationId == "apple") {
                    AppleSignInUser.consumeNameFromCurrentRequest()
                }
                return it
            }

        val resolvedEmail = email?.trim()?.takeIf { it.isNotEmpty() }
            ?: throw OAuth2AuthenticationException(
                "$provider did not return an email address; cannot create a new account",
            )

        userRepository.findByEmail(resolvedEmail)?.let { existing ->
            linkAccount(existing, provider, providerSubject)
            applyInitialProfile(existing, oauth2User, registrationId)
            assignDefaultSlugIfMissing(existing)
            return userRepository.save(existing)
        }

        val newUser = User(oauth2User).apply {
            applyInitialProfile(this, oauth2User, registrationId)
            assignDefaultSlugIfMissing(this)
        }
        val savedUser = userRepository.save(newUser)
        linkAccount(savedUser, provider, providerSubject)
        log.info("Registered new user via {} OAuth2: {}", provider, savedUser.email)
        return savedUser
    }

    private fun linkAccount(user: User, provider: String, providerSubject: String) {
        val alreadyLinked = connectedAccountRepository
            .findByProviderAndProviderIdWithUser(provider, providerSubject) != null
        if (alreadyLinked) {
            return
        }
        connectedAccountRepository.save(UserConnectedAccount(provider, providerSubject, user))
    }

    private fun applyInitialProfile(user: User, oauth2User: OAuth2User, registrationId: String) {
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

        if (registrationId == "apple") {
            AppleSignInUser.consumeNameFromCurrentRequest()?.let { appleName ->
                if (user.firstName.isNullOrBlank() && !appleName.firstName.isNullOrBlank()) {
                    user.firstName = appleName.firstName
                }
                if (user.lastName.isNullOrBlank() && !appleName.lastName.isNullOrBlank()) {
                    user.lastName = appleName.lastName
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
