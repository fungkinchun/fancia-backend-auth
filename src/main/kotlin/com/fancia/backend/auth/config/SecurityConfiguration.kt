package com.fancia.backend.auth.config

import com.fancia.backend.auth.core.user.service.OidcUserInfoService
import com.fancia.backend.auth.security.AppOidcUser
import com.fancia.backend.auth.security.GoogleOAuth2UserService
import com.fancia.backend.shared.user.core.entity.User
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.MediaType
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
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
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.*
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import java.util.function.Function

@Configuration
@EnableWebSecurity
class SecurityConfiguration(
    private val userDetailsService: UserDetailsService,
    private val oidcUserInfoService: OidcUserInfoService,
    private val oAuth2UserService: GoogleOAuth2UserService,
    private val registeredClientRepository: RegisteredClientRepository,
    private val authorizationService: OAuth2AuthorizationService,
    private val jwtSigningKeySource: JwtSigningKeySource,
    @Value("\${DOMAIN_NAME}") private val domainName: String,
) {
    @Bean
    @Order(1)
    fun authorizationServerSecurityFilterChain(
        http: HttpSecurity,
        authorizationServerSettings: AuthorizationServerSettings,
        jwtDecoder: JwtDecoder,
    ): SecurityFilterChain {
        val authorizationServerEndpoints = authorizationServerEndpointsMatcher()
        http.securityMatcher { request ->
            authorizationServerEndpoints.matches(request) &&
                    !OAUTH2_CLIENT_LOGIN_MATCHER.matches(request)
        }
        http.oauth2AuthorizationServer { authorizationServer ->
            authorizationServer
                .oidc { oidc ->
                    oidc.userInfoEndpoint { userInfo ->
                        userInfo.userInfoMapper(userInfoMapper(oidcUserInfoService))
                    }
                    oidc.clientRegistrationEndpoint { clientRegistration ->
                        clientRegistration.authenticationProviders(configureRegisteredClientConverter())
                    }
                    oidc.logoutEndpoint { logout ->
                        logout.authenticationProviders { providers ->
                            providers.removeIf { it is OidcLogoutAuthenticationProvider }
                            providers.add(
                                SpaOidcLogoutAuthenticationProvider(
                                    registeredClientRepository,
                                    authorizationService,
                                    jwtDecoder,
                                )
                            )
                        }
                    }
                }
        }.authorizeHttpRequests { authorize ->
            authorize.requestMatchers(authorizationServerSettings.oidcLogoutEndpoint, "/error").permitAll()
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
    fun defaultSecurityFilterChain(
        http: HttpSecurity,
        clientRegistrationRepository: ObjectProvider<ClientRegistrationRepository>,
    ): SecurityFilterChain {
        http.securityMatcher { request ->
            val path = request.servletPath ?: request.requestURI
            !isAuthorizationServerEndpoint(path)
        }
        http.authorizeHttpRequests { authorize ->
            authorize.requestMatchers(
                "/login",
                "/error",
                "/css/**",
                "/img/**",
                "/login/oauth2/code/**",
                "/callback",
                "/oauth2/authorization/**",
            ).permitAll()
            authorize.requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
            authorize.requestMatchers("/actuator/**").permitAll()
            authorize.anyRequest().authenticated()
        }.oauth2ResourceServer { it.jwt(Customizer.withDefaults()) }
            .formLogin { form ->
                form.loginPage("/login").loginProcessingUrl("/login").permitAll()
            }

        if (clientRegistrationRepository.ifAvailable != null) {
            val clients = clientRegistrationRepository.getObject()
            http.oauth2Login { oauth2 ->
                oauth2.loginPage("/login")
                    .authorizationEndpoint { endpoint ->
                        endpoint.authorizationRequestResolver(googleSelectAccountRequestResolver(clients))
                    }
                    .redirectionEndpoint { endpoint ->
                        endpoint.baseUri("/callback")
                    }
                    .userInfoEndpoint { userInfo ->
                        userInfo.oidcUserService(oAuth2UserService)
                    }
                    .successHandler(oauth2AuthenticationSuccessHandler())
                    .failureHandler(oauth2AuthenticationFailureHandler())
            }
        }

        return http.build()
    }

    private fun googleSelectAccountRequestResolver(
        clients: ClientRegistrationRepository,
    ): OAuth2AuthorizationRequestResolver {
        val resolver = DefaultOAuth2AuthorizationRequestResolver(
            clients,
            OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI,
        )
        resolver.setAuthorizationRequestCustomizer { customizer ->
            customizer.additionalParameters { params ->
                params["prompt"] = "select_account"
            }
        }
        return resolver
    }

    @Bean
    fun oauth2AuthenticationSuccessHandler(): AuthenticationSuccessHandler {
        return SavedRequestAwareAuthenticationSuccessHandler().apply {
            setDefaultTargetUrl("https://$domainName/")
        }
    }

    @Bean
    fun oauth2AuthenticationFailureHandler(): AuthenticationFailureHandler {
        return SimpleUrlAuthenticationFailureHandler("/login?oauth2Error")
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> = jwtSigningKeySource.createJwkSource()

    companion object {
        private val OAUTH2_CLIENT_LOGIN_MATCHER: RequestMatcher = RequestMatcher { request ->
            val path = request.servletPath ?: request.requestURI
            isOAuth2ClientLoginPath(path)
        }

        private fun isOAuth2ClientLoginPath(path: String): Boolean =
            path.startsWith("/oauth2/authorization/")

        private fun isAuthorizationServerEndpoint(path: String): Boolean {
            if (isOAuth2ClientLoginPath(path)) return false
            if (path.startsWith("/connect/") || path.startsWith("/.well-known/")) return true
            if (!path.startsWith("/oauth2/")) return false
            return path.startsWith("/oauth2/authorize") ||
                    path.startsWith("/oauth2/token") ||
                    path.startsWith("/oauth2/revoke") ||
                    path.startsWith("/oauth2/introspect") ||
                    path.startsWith("/oauth2/jwks") ||
                    path.startsWith("/oauth2/device")
        }

        private fun authorizationServerEndpointsMatcher(): RequestMatcher {
            return RequestMatcher { request ->
                val path = request.servletPath ?: request.requestURI
                isAuthorizationServerEndpoint(path)
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
        val principalName = context.authorization?.principalName
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.tokenType)) {
            val authentication = context.getPrincipal<Authentication>()
            authentication.let {
                val authorities = it.authorities.map { authority -> authority.authority }
                context.claims.claim("authorities", authorities)
                val user = resolveAuthenticatedUser(it, principalName)
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
                val user = resolveAuthenticatedUser(it, principalName)
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

    private fun resolveAuthenticatedUser(authentication: Authentication?, principalName: String? = null): User? {
        when (val principal = authentication?.principal) {
            is User -> return principal
            is AppOidcUser -> return principal.user
            is OAuth2User -> {
                principal.getAttribute<String>("email")?.let { return loadUserByEmail(it) }
            }

            is String -> return loadUserByEmail(principal)
        }
        principalName?.let { return loadUserByEmail(it) }
        return null
    }

    private fun loadUserByEmail(email: String): User? {
        return try {
            userDetailsService.loadUserByUsername(email) as User
        } catch (_: BadCredentialsException) {
            null
        }
    }
}