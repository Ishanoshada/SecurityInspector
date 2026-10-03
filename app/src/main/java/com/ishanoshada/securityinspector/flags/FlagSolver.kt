package com.ishanoshada.securityinspector.flags

object FlagSolver {
    const val FLAG_STATIC = "flag_static"
    const val FLAG_DYNAMIC = "flag_dynamic"

    fun stepsFor(flagId: String): List<FlagStep> = when (flagId) {
        FLAG_STATIC -> StaticFlagVault.trace()
        FLAG_DYNAMIC -> DynamicFlagVault.trace()
        else -> emptyList()
    }

    fun finalFlag(flagId: String): String = when (flagId) {
        FLAG_STATIC -> StaticFlagVault.reveal()
        FLAG_DYNAMIC -> DynamicFlagVault.getFlag()
        else -> ""
    }
}
