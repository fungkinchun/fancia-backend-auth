package com.fancia.backend.auth.core.client.repository

import com.fancia.backend.auth.core.client.entity.Client
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface ClientRepository : JpaRepository<Client, String> {
    fun findByClientId(clientId: String): Client?
}