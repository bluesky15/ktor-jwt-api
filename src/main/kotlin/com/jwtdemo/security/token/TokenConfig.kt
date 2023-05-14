package com.jwtdemo.security.token

data class TokenConfig (
    val issuer:String,
    val audience:String,
    var expiresIn:Long,
    val secret:String
)