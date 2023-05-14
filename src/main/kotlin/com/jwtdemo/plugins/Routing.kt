package com.jwtdemo.plugins

import ch.qos.logback.core.subst.Token
import com.jwtdemo.data.user.UserDataSource
import com.jwtdemo.route.authenticate
import com.jwtdemo.route.getSecretInfo
import com.jwtdemo.route.signIn
import com.jwtdemo.route.signUp
import com.jwtdemo.security.hashing.HashingService
import com.jwtdemo.security.token.TokenConfig
import com.jwtdemo.security.token.TokenService
import io.ktor.server.application.*
import io.ktor.server.routing.*

fun Application.configureRouting(
    userDataSource: UserDataSource,
    hashingService: HashingService,
    tokenService:TokenService,
    tokenConfig: TokenConfig,
    refreshTokenConfig:TokenConfig
) {
    routing {

        signIn(userDataSource,hashingService,tokenService,tokenConfig, refreshTokenConfig)
        signUp(hashingService,userDataSource)
        authenticate()
        getSecretInfo()
    }
}
