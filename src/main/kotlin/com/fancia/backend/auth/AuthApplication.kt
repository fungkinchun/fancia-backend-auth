package com.fancia.backend.auth

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.persistence.autoconfigure.EntityScan
import org.springframework.boot.runApplication

@EntityScan(
    basePackages = [
        "com.fancia.backend.auth",
        "com.fancia.backend.shared.user.core.entity"
    ]
)
@SpringBootApplication
class AuthApplication

fun main(args: Array<String>) {
    runApplication<AuthApplication>(*args)
}
