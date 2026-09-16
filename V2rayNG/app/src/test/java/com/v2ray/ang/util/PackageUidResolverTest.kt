package com.v2ray.ang.util

import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import com.tencent.mmkv.MMKV
import com.v2ray.ang.handler.MmkvManager
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import org.mockito.Mockito.mockStatic
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class PackageUidResolverTest {
    @Test fun `root refresh observes a changed UID and evicts an uninstalled package`() {
        val context = mock<Context>()
        val packages = mock<PackageManager>()
        whenever(context.packageManager).thenReturn(packages)
        val name = "test.reinstalled.application"
        whenever(packages.getPackageUid(name, 0)).thenReturn(10421)
        assertEquals(listOf("10421"), PackageUidResolver.packageNamesToUids(context, listOf(name), refresh = true))
        whenever(packages.getPackageUid(name, 0)).thenReturn(10422)
        assertEquals(listOf("10421"), PackageUidResolver.packageNamesToUids(context, listOf(name)))
        assertEquals(listOf("10422"), PackageUidResolver.packageNamesToUids(context, listOf(name), refresh = true))

        whenever(packages.getPackageUid(name, 0)).thenThrow(mock<PackageManager.NameNotFoundException>())
        mockStatic(Log::class.java).use {
            assertTrue(PackageUidResolver.packageNamesToUids(context, listOf(name), refresh = true).isEmpty())
        }
        assertFalse(PackageUidResolver.packageUidMap.containsKey(name))
    }

    @Test fun `root refresh uses the current context user instead of the cached user`() {
        val name = "test.profile.application"
        for (uid in listOf(10421, 1010421)) {
            val context = mock<Context>()
            val packages = mock<PackageManager>()
            whenever(context.packageManager).thenReturn(packages)
            whenever(packages.getPackageUid(name, 0)).thenReturn(uid)
            assertEquals(listOf(uid.toString()), PackageUidResolver.packageNamesToUids(context, listOf(name), refresh = true))
        }
    }

    companion object {
        @BeforeClass @JvmStatic fun initializeLogSettings() {
            val settings = mock<MMKV>()
            mockStatic(MMKV::class.java).use {
                it.`when`<MMKV> { MMKV.mmkvWithID("SETTING", MMKV.MULTI_PROCESS_MODE) }.thenReturn(settings)
                MmkvManager.decodeSettingsString("test-initialize")
            }
        }
    }
}
