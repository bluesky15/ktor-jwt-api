package com.jwtdemo

import com.jwtdemo.data.user.MongoUserDataSource
import com.jwtdemo.data.user.User
import io.ktor.server.application.*
import com.jwtdemo.plugins.*
import com.jwtdemo.security.hashing.SHA256HashingService
import com.jwtdemo.security.token.JwtTokenService
import com.jwtdemo.security.token.TokenConfig
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import org.litote.kmongo.reactivestreams.KMongo
import org.litote.kmongo.coroutine.*

fun main(args: Array<String>): Unit =
    io.ktor.server.netty.EngineMain.main(args)

@Suppress("unused") // application.conf references the main function. This annotation prevents the IDE from marking it as unused.
fun Application.module() {
    val mongoPw = System.getenv("MONGO_PW")
    val dbName = "ktor-auth"
    val db =
        KMongo.createClient(connectionString = "mongodb+srv://lkbcluster:$mongoPw@mongodb1.ez2fygg.mongodb.net/ktor-auth?retryWrites=true&w=majority").coroutine.getDatabase(
            dbName
        )
    val userDataSource = MongoUserDataSource(db)
//    GlobalScope.launch {
//        val user = User(userName = "test", password = "test-password", salt = "salt")
//        userDataSource.insertUser(user)
//    }

    val tokenService = JwtTokenService()
    val tokenConfig = TokenConfig(
        issuer = environment.config.property("jwt.issuer").getString(),
        audience = environment.config.property("jwt.audience").getString(),
        expiresIn = 60L*1000L,
        secret = System.getenv("JWT_SECRET")
    )
    val refreshTokenConfig = tokenConfig.copy()
    refreshTokenConfig.expiresIn = 24L*60L*60L*1000L
    val hashingService = SHA256HashingService()



    configureSerialization()
    configureMonitoring()
    configureSecurity(tokenConfig)
    configureRouting(userDataSource, hashingService, tokenService, tokenConfig, refreshTokenConfig)
}
