package com.jwtdemo.security.hashing

data class SaltedHash(val hash: String, val salt: String)
