package com.fancia.backend.auth.config

import com.fancia.backend.auth.core.user.service.OidcUserInfoService
import com.fancia.backend.shared.user.core.entity.User
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.MediaType
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*
import java.util.function.Function

@Configuration
@EnableWebSecurity
class SecurityConfiguration(
    private val userDetailsService: UserDetailsService, private val oidcUserInfoService: OidcUserInfoService
) {
    @Bean
    @Order(1)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http.oauth2AuthorizationServer { authorizationServer ->
            http.securityMatcher(authorizationServer.endpointsMatcher)
            authorizationServer
                .oidc { oidc ->
                    oidc.userInfoEndpoint { userInfo ->
                        userInfo.userInfoMapper(userInfoMapper(oidcUserInfoService))
                    }
                    oidc.clientRegistrationEndpoint { clientRegistration ->
                        clientRegistration.authenticationProviders(configureRegisteredClientConverter())
                    }
                }
        }.authorizeHttpRequests { authorize ->
            authorize.anyRequest().authenticated()
        }.exceptionHandling { exceptions ->
            exceptions.defaultAuthenticationEntryPointFor(
                LoginUrlAuthenticationEntryPoint("/login"), MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            )
        }
        return http.build()
    }

    @Bean
    @Order(2)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http.authorizeHttpRequests { authorize ->
            authorize.anyRequest().authenticated()
        }.oauth2ResourceServer { it.jwt(Customizer.withDefaults()) }.formLogin(Customizer.withDefaults())
        return http.build()
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyPair = generateRsaKey()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey
        val rsaKey = RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build()
        val jwkSet = JWKSet(rsaKey)
        return ImmutableJWKSet(jwkSet)
    }

    companion object {
        private fun generateRsaKey(): KeyPair {
            return try {
                val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
                keyPairGenerator.initialize(2048)
                keyPairGenerator.generateKeyPair()
            } catch (ex: Exception) {
                throw IllegalStateException(ex)
            }
        }
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    }

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings {
        return AuthorizationServerSettings.builder().build()
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    @Bean
    fun authenticationManager(): AuthenticationManager {
        val daoAuthenticationProvider = DaoAuthenticationProvider(userDetailsService)
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder())
        return ProviderManager(daoAuthenticationProvider)
    }

    @Bean
    fun jwtCustomizer(): OAuth2TokenCustomizer<JwtEncodingContext> = OAuth2TokenCustomizer { context ->
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.tokenType)) {
            val authentication = context.getPrincipal<Authentication>()
            authentication.let {
                val authorities = it.authorities.map { authority -> authority.authority }
                context.claims.claim("authorities", authorities)
                val user = it?.principal as? User
                user?.let { user ->
                    context.claims.claim("email", user.email)
                    context.claims.claim("name", "${user.firstName} ${user.lastName}")
                    context.claims.claim("userId", user.id)
                }
            }
        }
        if (OidcParameterNames.ID_TOKEN == context.tokenType.value) {
            val authentication = context.getPrincipal<Authentication>()
            authentication.let {
                val user = it?.principal as? User
                user?.let { user ->
                    context.claims.claim("name", "${user.firstName} ${user.lastName}")
                    context.claims.claim("email", user.email)
                    context.claims.claim("userId", user.id)
                    user.profileImageUrl?.let {
                        context.claims.claim("profileImageUrl", user.profileImageUrl)
                    }
                }
            }
        }
    }

    @Bean
    fun userInfoMapper(
        oidcUserInfoService: OidcUserInfoService
    ): Function<OidcUserInfoAuthenticationContext, OidcUserInfo> {
        return Function { context ->
            val authentication = context.getAuthentication<OidcUserInfoAuthenticationToken>()
            val user = oidcUserInfoService.loadUser(authentication.name)
            OidcUserInfo(user.claims)
        }
    }

    private fun configureRegisteredClientConverter(): (List<AuthenticationProvider>) -> Unit {
        return { authenticationProviders ->
            authenticationProviders.forEach { authenticationProvider ->
                if (authenticationProvider is OidcClientRegistrationAuthenticationProvider) {
                    authenticationProvider.setRegisteredClientConverter(CustomRegisteredClientConverter())
                }
            }
        }
    }
}