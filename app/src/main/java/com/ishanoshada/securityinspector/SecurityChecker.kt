package com.ishanoshada.securityinspector

import android.content.Context
import com.ishanoshada.securityinspector.checks.DynamicLoadingChecker
import com.ishanoshada.securityinspector.checks.FridaChecker
import com.ishanoshada.securityinspector.checks.HookIntegrityChecker
import com.ishanoshada.securityinspector.checks.LsposedChecker
import com.ishanoshada.securityinspector.checks.NetworkSecurityChecker
import com.ishanoshada.securityinspector.checks.RootChecker
import com.ishanoshada.securityinspector.checks.RuntimeExecChecker
import com.ishanoshada.securityinspector.checks.SystemEnvironmentChecker
import com.ishanoshada.securityinspector.checks.VirtualAppChecker
import com.ishanoshada.securityinspector.models.SecurityCategory

object SecurityChecker {

    fun runAllChecks(context: Context): List<SecurityCategory> {
        return listOf(
            FridaChecker.getFridaChecks(),
            RootChecker.getDeepRootChecks(),
            RootChecker.getRootPackagesChecks(context),
            LsposedChecker.getLsposedChecks(),
            NetworkSecurityChecker.getNetworkSecurityChecks(),
            VirtualAppChecker.getVirtualAppChecks(context),
            RuntimeExecChecker.getRuntimeExecChecks(),
            DynamicLoadingChecker.getDynamicLoadingChecks(context),
            HookIntegrityChecker.getHookIntegrityChecks(),
            SystemEnvironmentChecker.getDebuggerAndToolsChecks(context),
            SystemEnvironmentChecker.getAdbDeveloperChecks(context),
            SystemEnvironmentChecker.getEmulatorChecks(context),
            SystemEnvironmentChecker.getBuildIntegrityChecks(),
            SystemEnvironmentChecker.getEnvironmentMountChecks(),
        )
    }
}
