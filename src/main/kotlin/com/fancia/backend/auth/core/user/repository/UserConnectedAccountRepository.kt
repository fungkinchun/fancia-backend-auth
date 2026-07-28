package com.fancia.backend.auth.core.user.repository

import com.fancia.backend.shared.user.core.entity.UserConnectedAccount
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import org.springframework.stereotype.Repository
import java.util.*

@Repository
interface UserConnectedAccountRepository : JpaRepository<UserConnectedAccount, UUID> {
    @Query(
        """
        SELECT ca FROM UserConnectedAccount ca
        JOIN FETCH ca.user
        WHERE ca.provider = :provider AND ca.providerId = :providerId
        """
    )
    fun findByProviderAndProviderIdWithUser(
        @Param("provider") provider: String,
        @Param("providerId") providerId: String,
    ): UserConnectedAccount?
}
