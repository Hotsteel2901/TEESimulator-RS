package org.matrix.TEESimulator.config

import android.os.Handler
import android.os.HandlerThread
import java.io.File
import java.net.URL
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import javax.net.ssl.HttpsURLConnection
import org.json.JSONArray
import org.json.JSONObject
import org.matrix.TEESimulator.BuildConfig
import org.matrix.TEESimulator.logging.SystemLogger

object BulletinPoller {
    private const val BULLETIN_URL = "https://source.android.com/docs/security/bulletin/pixel"
    private const val PATCH_FILE = "/data/adb/tricky_store/security_patch.txt"
    private const val HISTORY_FILE = "/data/adb/tricky_store/last_bulletin_fetch.json"
    private const val HISTORY_STAGING = "/data/adb/tricky_store/last_bulletin_fetch.json.next"
    private const val HISTORY_CAP = 10
    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 15_000
    private const val STEADY_INTERVAL_MS = 24L * 60 * 60 * 1000

    private val BOOTSTRAP_INTERVALS = longArrayOf(5_000, 30_000, 120_000, 600_000, 1_800_000)
    private val DATE_REGEX = Regex("<td>(\\d{4}-\\d{2}-\\d{2})</td>")

    private lateinit var handler: Handler
    @Volatile private var bootstrapStep = 0
    @Volatile private var steadyArmed = false

    fun start() {
        val thread = HandlerThread("BulletinPoller").apply { start() }
        handler = Handler(thread.looper)
        handler.postDelayed(::pollOnce, BOOTSTRAP_INTERVALS[0])
    }

    private fun pollOnce() {
        try {
            val result = fetchAndParse()
            appendHistory(result)
            scheduleNext(result.status == "success")
        } catch (t: Throwable) {
            SystemLogger.error("BulletinPoller: pollOnce failed", t)
            scheduleNext(false)
        }
    }

    private fun scheduleNext(success: Boolean) {
        if (success || steadyArmed) {
            steadyArmed = true
            handler.postDelayed(::pollOnce, STEADY_INTERVAL_MS)
            return
        }
        bootstrapStep++
        if (bootstrapStep >= BOOTSTRAP_INTERVALS.size) {
            steadyArmed = true
            handler.postDelayed(::pollOnce, STEADY_INTERVAL_MS)
        } else {
            handler.postDelayed(::pollOnce, BOOTSTRAP_INTERVALS[bootstrapStep])
        }
    }

    private data class FetchResult(
        val ts: Long,
        val status: String,
        val httpCode: Int?,
        val parsedDate: String?,
        val applied: Boolean,
        val error: String?,
    )

    private fun fetchAndParse(): FetchResult {
        val ts = System.currentTimeMillis()
        var conn: HttpsURLConnection? = null
        return try {
            conn =
                (URL(BULLETIN_URL).openConnection() as HttpsURLConnection).apply {
                    connectTimeout = CONNECT_TIMEOUT_MS
                    readTimeout = READ_TIMEOUT_MS
                    setRequestProperty(
                        "User-Agent",
                        "TEESimulator/${BuildConfig.VERSION_NAME}",
                    )
                    requestMethod = "GET"
                }
            val code = conn.responseCode
            if (code != 200) {
                return FetchResult(ts, "network_error", code, null, false, "HTTP $code")
            }
            val html = conn.inputStream.bufferedReader().use { it.readText() }
            val date = DATE_REGEX.find(html)?.groupValues?.get(1)
            if (date == null) {
                return FetchResult(
                    ts,
                    "parse_error",
                    code,
                    null,
                    false,
                    "no <td>YYYY-MM-DD</td> match",
                )
            }
            val current = currentPatch()
            if (current == null) {
                return FetchResult(ts, "success", code, date, false, null)
            }
            val isNewer = date > current
            if (isNewer) {
                PatchLevelManager.updateTo(date)
            }
            FetchResult(ts, "success", code, date, isNewer, null)
        } catch (e: Exception) {
            FetchResult(ts, "network_error", null, null, false, e.toString())
        } finally {
            conn?.disconnect()
        }
    }

    private fun currentPatch(): String? {
        val f = File(PATCH_FILE)
        if (!f.exists()) return null
        return try {
            f.readLines()
                .firstOrNull { it.startsWith("system=") }
                ?.substringAfter("system=")
                ?.trim()
                ?.takeIf { it != "prop" && it.isNotEmpty() }
        } catch (_: Exception) {
            null
        }
    }

    private fun appendHistory(result: FetchResult) {
        try {
            val target = File(HISTORY_FILE)
            val staging = File(HISTORY_STAGING)
            val existing = if (target.exists()) runCatching { target.readText() }.getOrNull() else null
            val history =
                existing
                    ?.let { runCatching { JSONObject(it).optJSONArray("history") }.getOrNull() }
                    ?: JSONArray()
            val entry =
                JSONObject().apply {
                    put("ts", result.ts)
                    put("status", result.status)
                    put("http_code", result.httpCode ?: JSONObject.NULL)
                    put("parsed_date", result.parsedDate ?: JSONObject.NULL)
                    put("applied", result.applied)
                    put("error", result.error ?: JSONObject.NULL)
                }
            history.put(entry)
            while (history.length() > HISTORY_CAP) history.remove(0)

            val latestKnown =
                (0 until history.length())
                    .mapNotNull {
                        history.optJSONObject(it)?.optString("parsed_date", "")?.takeIf { d ->
                            d.isNotBlank()
                        }
                    }
                    .lastOrNull()

            val root =
                JSONObject().apply {
                    put("latest_known_date", latestKnown ?: JSONObject.NULL)
                    put("history", history)
                }
            staging.writeText(root.toString(2))
            Files.move(
                staging.toPath(),
                target.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
        } catch (e: Exception) {
            SystemLogger.error("BulletinPoller: failed to persist history", e)
        }
    }
}
