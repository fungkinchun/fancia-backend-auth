package com.fancia.backend.auth.core.client.repository

import com.fancia.backend.auth.core.client.entity.Authorization
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import org.springframework.stereotype.Repository

@Repository
interface AuthorizationRepository : JpaRepository<Authorization, String> {
    fun findByState(state: String): Authorization?
    fun findByAuthorizationCodeValue(authorizationCode: String): Authorization?
    fun findByAccessTokenValue(accessToken: String): Authorization?
    fun findByRefreshTokenValue(refreshToken: String): Authorization?
    fun findByOidcIdTokenValue(idToken: String): Authorization?
    fun findByUserCodeValue(userCode: String): Authorization?
    fun findByDeviceCodeValue(deviceCode: String): Authorization?

    @Query(
        """SELECT a FROM Authorization a WHERE a.state = :token
            OR a.authorizationCodeValue = :token
            OR a.accessTokenValue = :token
            OR a.refreshTokenValue = :token
            OR a.oidcIdTokenValue = :token
            OR a.userCodeValue = :token
            OR a.deviceCodeValue = :token"""
    )
    fun findByAnyToken(@Param("token") token: String): Authorization?
}