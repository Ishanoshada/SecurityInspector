package com.ishanoshada.securityinspector.models

data class SecurityCheckItem(
    val id: String,
    val name: String,
    val description: String,
    val isDetected: Boolean,
    val functionName: String,
    val methodsAndApis: List<String>,
    val technicalExplanation: String,
    val exampleCode: String,
)

data class SecurityCategory(
    val categoryName: String,
    val iconEmoji: String,
    val items: List<SecurityCheckItem>,
)
