package com.jwtdemo.responses

import kotlinx.serialization.Serializable

@Serializable
data class AuthResponse (val accessToken:String, val refreshToken:String)