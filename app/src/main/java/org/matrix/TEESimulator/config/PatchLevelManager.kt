package org.matrix.TEESimulator.config

import android.os.Build
import android.os.SystemProperties
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.time.LocalDate
import org.json.JSONObject
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.util.AndroidDeviceUtils

object PatchLevelManager {
    private const val PATCH_FILE = "/data/adb/tricky_store/security_patch.txt"
    private const val STAGING_FILE = "/data/adb/tricky_store/security_patch.txt.next"
    private const val FLOOR_YYYYMMDD = 20200101
    private const val MAX_PAST_OFFSET = 10000
    private const val MAX_FUTURE_DAYS = 60L

    private val DATE_PATTERN = Regex("^\\d{4}-\\d{2}-\\d{2}$")
    private val PROP_PATTERN = Regex("^SECURITY_PATCH=(.+)$", RegexOption.MULTILINE)
    private val SECTION_HEADER = Regex("^\\[[a-zA-Z0-9_.-]+]$")
    private val GLOBAL_KEYS = setOf("system", "boot", "vendor", "all")

    private val PIF_SOURCES =
        listOf(
            "/data/adb/modules/playintegrityfix/pif.json",
            "/data/adb/pif.json",
            "/data/adb/modules/playintegrityfix/pif.prop",
            "/data/adb/pif.prop",
            "/data/adb/modules/playintegrityfix/custom.pif.json",
            "/data/adb/modules/playintegrityfix/custom.pif.prop",
        )

    fun initialize() {
        val date =
            resolvePifPatch()
                ?: SystemProperties.get(
                    "ro.build.version.security_patch",
                    Build.VERSION.SECURITY_PATCH,
                )
        SystemLogger.info("PatchLevelManager: resolved patch date = $date")
        applyToProps(date)
    }

    private fun applyToProps(date: String) {
        if (!DATE_PATTERN.matches(date)) {
            SystemLogger.warning(
                "PatchLevelManager: skip resetprop for invalid date: $date"
            )
            return
        }
        AndroidDeviceUtils.setProperty("ro.build.version.security_patch", date)
        AndroidDeviceUtils.setProperty("ro.vendor.build.security_patch", date)
    }

    fun updateTo(date: String) {
        if (!DATE_PATTERN.matches(date)) {
            SystemLogger.warning("PatchLevelManager: invalid date format: $date")
            return
        }
        val dateInt = date.replace("-", "").toInt()
        if (dateInt < FLOOR_YYYYMMDD) {
            SystemLogger.warning("PatchLevelManager: $date below floor $FLOOR_YYYYMMDD")
            return
        }
        val now = LocalDate.now()
        val today = now.year * 10000 + now.monthValue * 100 + now.dayOfMonth
        if (today >= dateInt + MAX_PAST_OFFSET) {
            SystemLogger.warning(
                "PatchLevelManager: $date more than 1y older than today ($today)"
            )
            return
        }
        val maxFuture =
            now.plusDays(MAX_FUTURE_DAYS).let {
                it.year * 10000 + it.monthValue * 100 + it.dayOfMonth
            }
        if (dateInt > maxFuture) {
            SystemLogger.warning(
                "PatchLevelManager: $date more than $MAX_FUTURE_DAYS days in future ($maxFuture)"
            )
            return
        }
        try {
            atomicWrite(date)
        } catch (e: Exception) {
            SystemLogger.error("PatchLevelManager: atomicWrite failed for $date", e)
            return
        }
        applyToProps(date)
        SystemLogger.info("PatchLevelManager: applied patch date $date")
    }

    private fun resolvePifPatch(): String? {
        val source = PIF_SOURCES.map(::File).lastOrNull { it.exists() } ?: return null
        return try {
            val text = source.readText()
            val parsed =
                if (source.name.endsWith(".json")) {
                    JSONObject(text).optString("SECURITY_PATCH", "")
                } else {
                    PROP_PATTERN.find(text)?.groupValues?.get(1)?.trim().orEmpty()
                }
            parsed.takeIf { it.isNotBlank() }
        } catch (e: Exception) {
            SystemLogger.warning(
                "PatchLevelManager: failed to parse ${source.path}: ${e.message}"
            )
            null
        }
    }

    private fun atomicWrite(date: String) {
        val target = File(PATCH_FILE)
        val staging = File(STAGING_FILE)
        staging.writeText(mergedContents(target, date))
        Files.move(
            staging.toPath(),
            target.toPath(),
            StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING,
        )
    }

    private fun mergedContents(target: File, date: String): String {
        val globalBlock = "system=$date\nboot=$date\nvendor=$date\n"
        if (!target.exists()) return globalBlock
        val tail =
            runCatching { stripGlobalAssignments(target.readLines()) }.getOrNull()
                ?: return globalBlock
        if (tail.isEmpty()) return globalBlock
        return globalBlock + tail.joinToString("\n", prefix = "\n", postfix = "\n")
    }

    private fun stripGlobalAssignments(lines: List<String>): List<String> {
        val kept = mutableListOf<String>()
        var inGlobal = true
        for (line in lines) {
            val trimmed = line.trim()
            if (SECTION_HEADER.matches(trimmed)) {
                inGlobal = false
                kept += line
                continue
            }
            if (inGlobal && isGlobalKeyAssignment(trimmed)) continue
            kept += line
        }
        return kept
    }

    private fun isGlobalKeyAssignment(trimmed: String): Boolean {
        if (trimmed.isEmpty() || trimmed.startsWith("#")) return false
        val key = trimmed.substringBefore("=").trim().lowercase()
        return key in GLOBAL_KEYS
    }
}
