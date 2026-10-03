package com.ishanoshada.securityinspector.flags

data class FlagStep(
    val index: Int,
    val title: String,
    val input: String,
    val operation: String,
    val output: String,
    val explanation: String,
    val toolHint: String
)
