package com.fancia.backend.auth.config

import org.springframework.core.convert.converter.Converter
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator
import org.springframework.security.crypto.keygen.StringKeyGenerator
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType
import org.springframework.security.oauth2.jose.jws.MacAlgorithm
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.util.CollectionUtils
import java.time.Instant
import java.util.*
import java.util.function.Consumer

/**
 * A {@link Converter} that transforms an {@link OidcClientRegistration} into a {@link RegisteredClient}
 * for use with Spring Authorization Server.
 *
 * <p>
 * <b>Key difference from {@link OidcClientRegistrationRegisteredClientConverter}:</b>
 * This converter determines client authentication methods from the registration's <b>client_authentication_methods</b>
 * claim, rather than the standard <b>token_endpoint_auth_method</b> field. This enables more flexible and
 * customizable client authentication configurations during dynamic client registration.
 * </p>
 */
class CustomRegisteredClientConverter : Converter<OidcClientRegistration, RegisteredClient> {
    companion object {
        val CLIENT_ID_GENERATOR: StringKeyGenerator = Base64StringKeyGenerator(
            Base64.getUrlEncoder().withoutPadding(), 32
        )
        val CLIENT_SECRET_GENERATOR: StringKeyGenerator = Base64StringKeyGenerator(
            Base64.getUrlEncoder().withoutPadding(), 48
        )
    }

    override fun convert(clientRegistration: OidcClientRegistration): RegisteredClient {
        val builder = RegisteredClient.withId(UUID.randomUUID().toString()).clientId(CLIENT_ID_GENERATOR.generateKey())
            .clientIdIssuedAt(Instant.now()).clientName(clientRegistration.clientName)
        val methods = clientRegistration.getClaimAsStringList("client_authentication_methods")
        methods.forEach { method ->
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.valueOf(method))
            when (method) {
                ClientAuthenticationMethod.CLIENT_SECRET_POST.value -> {
                    builder.clientSecret(CLIENT_SECRET_GENERATOR.generateKey())
                }

                ClientAuthenticationMethod.CLIENT_SECRET_JWT.value -> {
                    builder.clientSecret(CLIENT_SECRET_GENERATOR.generateKey())
                }

                ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value -> {
                    builder.clientSecret(CLIENT_SECRET_GENERATOR.generateKey())
                }
            }
        }

        builder.redirectUris(Consumer { it.addAll(clientRegistration.redirectUris) })

        if (!CollectionUtils.isEmpty(clientRegistration.postLogoutRedirectUris)) {
            builder.postLogoutRedirectUris(Consumer { it.addAll(clientRegistration.postLogoutRedirectUris) })
        }

        if (!CollectionUtils.isEmpty(clientRegistration.grantTypes)) {
            builder.authorizationGrantTypes(Consumer { set ->
                clientRegistration.grantTypes.forEach { set.add(AuthorizationGrantType(it)) }
            })
        } else {
            builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        }

        if (CollectionUtils.isEmpty(clientRegistration.responseTypes) || clientRegistration.responseTypes.contains(
                OAuth2AuthorizationResponseType.CODE.value
            )
        ) {
            builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        }

        if (!CollectionUtils.isEmpty(clientRegistration.scopes)) {
            builder.scopes(Consumer { it.addAll(clientRegistration.scopes) })
        }
        val clientSettingsBuilder = ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(true)

        when (clientRegistration.tokenEndpointAuthenticationMethod) {
            ClientAuthenticationMethod.CLIENT_SECRET_JWT.value -> {
                var macAlgorithm = MacAlgorithm.from(clientRegistration.tokenEndpointAuthenticationSigningAlgorithm)
                if (macAlgorithm == null) {
                    macAlgorithm = MacAlgorithm.HS256
                }
                clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(macAlgorithm)
            }

            ClientAuthenticationMethod.PRIVATE_KEY_JWT.value -> {
                var signatureAlgorithm =
                    SignatureAlgorithm.from(clientRegistration.tokenEndpointAuthenticationSigningAlgorithm)
                if (signatureAlgorithm == null) {
                    signatureAlgorithm = SignatureAlgorithm.RS256
                }
                clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(signatureAlgorithm)
                clientSettingsBuilder.jwkSetUrl(clientRegistration.jwkSetUrl.toString())
            }
        }

        builder.clientSettings(clientSettingsBuilder.build()).tokenSettings(
            TokenSettings.builder().idTokenSignatureAlgorithm(SignatureAlgorithm.RS256).build()
        )

        return builder.build()
    }
}