package com.kpgc.timerroot

import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.os.SystemClock
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircleOutline
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.RemoveCircleOutline
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import rikka.shizuku.Shizuku
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.ScrollBehavior
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.basic.rememberTopAppBarState
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Close
import top.yukonga.miuix.kmp.icon.extended.Copy
import top.yukonga.miuix.kmp.overlay.OverlayBottomSheet
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.darkColorScheme
import top.yukonga.miuix.kmp.theme.lightColorScheme
import top.yukonga.miuix.kmp.utils.PressFeedbackType
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

/**
 * Front end for CVE-2026-98260 (posix CPU timer UAF).
 *
 * The exploit cannot run in this process (an app is untrusted_app and cannot
 * read /sys/kernel/tracing), so it runs through a Shizuku user service that
 * Shizuku starts as the shell user (uid 2000, u:r:shell:s0).
 */
class MainActivity : ComponentActivity() {

    private val TAG = "TimerRoot"
    private val REQUEST_CODE = 1001
    private val SHIZUKU_PACKAGE = "moe.shizuku.privileged.api"

    // Compose-observable state.
    private val service = mutableStateOf<IUserService?>(null)
    private val bound = mutableStateOf(false)
    private val rootOpen = mutableStateOf(false)
    private val ksud = mutableStateOf("-")
    private val ksu = mutableStateOf("unknown")
    private val selinux = mutableStateOf("-")
    private val seccomp = mutableStateOf("-")
    private val shizukuRunning = mutableStateOf(false)
    private val shizukuPermission = mutableStateOf(-1)
    private val rootFailed = mutableStateOf(false)
    private val loadingKsu = mutableStateOf(false)
    private val logSheetVisible = mutableStateOf(false)
    private val logLines = mutableStateListOf<String>()

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            service.value = IUserService.Stub.asInterface(binder)
            bound.value = true
            addLog("user service connected")
            refreshDetails()
        }

        override fun onServiceDisconnected(name: ComponentName) {
            service.value = null
            bound.value = false
            addLog("user service disconnected")
            refreshDetails()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.i(TAG, "onCreate")
        setContent {
            MiuixTheme(
                colors = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme(),
            ) {
                TimerRootApp()
            }
        }
        addLog("TimerRoot ready")
        refreshDetails()
        if (safePing() && safePermission() == 0) bindService()
    }

    override fun onResume() {
        super.onResume()
        refreshDetails()
    }

    // -------------------------------------------------------------- UI

    @Composable
    private fun TimerRootApp() {
        val scrollBehavior = MiuixScrollBehavior(rememberTopAppBarState())
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            topBar = {
                TopAppBar(
                    title = "TimerRoot",
                    scrollBehavior = scrollBehavior,
                )
            },
        ) { paddingValues ->
            MainContent(scrollBehavior, paddingValues)
            // OverlayBottomSheet registers with the Scaffold's popup host.
            LogSheet()
        }
    }

    @Composable
    private fun MainContent(
        scrollBehavior: ScrollBehavior,
        scaffoldPadding: PaddingValues,
    ) {
        LazyColumn(
            modifier = Modifier
                .scrollEndHaptic()
                .overScrollVertical()
                .fillMaxHeight()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .imePadding(),
            contentPadding = pageContentPadding(scaffoldPadding),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "controls") {
                ControlPanel()
            }
            item(key = "run") {
                RunButton()
            }
            item(key = "tools") {
                Card(modifier = Modifier.fillMaxWidth().padding(top = 12.dp)) {
                    ArrowPreference(
                        title = stringResource(R.string.pref_shizuku),
                        summary = if (shizukuRunning.value) {
                            stringResource(
                                if (bound.value) R.string.pref_shizuku_running_bound
                                else R.string.pref_shizuku_running_unbound
                            )
                        } else {
                            stringResource(R.string.pref_shizuku_start)
                        },
                        onClick = ::showShizuku,
                    )
                    ArrowPreference(
                        title = stringResource(R.string.pref_diagnose),
                        summary = stringResource(R.string.pref_diagnose_summary),
                        onClick = {
                            logSheetVisible.value = true
                            if (!loadingKsu.value) run("ids", "ids")
                        },
                    )
                    ArrowPreference(
                        title = stringResource(R.string.pref_log),
                        summary = stringResource(R.string.pref_log_summary),
                        onClick = { logSheetVisible.value = true },
                    )
                }
            }
            item(key = "reboot") {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    onClick = { if (!loadingKsu.value) confirmReboot() },
                    showIndication = true,
                    pressFeedbackType = PressFeedbackType.Tilt,
                ) {
                    ArrowPreference(
                        title = stringResource(R.string.action_reboot),
                        summary = stringResource(R.string.summary_reboot),
                        onClick = { if (!loadingKsu.value) confirmReboot() },
                    )
                }
            }
            item(key = "hint") {
                Text(
                    text = stringResource(R.string.hint_first_run),
                    fontSize = 12.sp,
                    color = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.55f),
                    modifier = Modifier.padding(start = 4.dp, end = 4.dp),
                )
            }
        }
    }

    @Composable
    private fun ControlPanel() {
        Column {
            ActivationStatusCard()
            DeviceInfoCard()
        }
    }

    @Composable
    private fun ActivationStatusCard() {
        val state = statusState()
        val backgroundColor = when (state.kind) {
            StatusKind.OK -> if (MiuixTheme.isDynamicColor) {
                MiuixTheme.colorScheme.secondaryContainer
            } else if (isSystemInDarkTheme()) Color(0xFF1A3825) else Color(0xFFDFFAE4)

            StatusKind.MISSING -> MiuixTheme.colorScheme.errorContainer
            else -> if (MiuixTheme.isDynamicColor) {
                MiuixTheme.colorScheme.tertiaryContainer
            } else if (isSystemInDarkTheme()) Color(0xFF3E2F1B) else Color(0xFFFFF0DB)
        }
        val icon: ImageVector = when (state.kind) {
            StatusKind.OK -> Icons.Rounded.CheckCircleOutline
            StatusKind.MISSING -> Icons.Rounded.RemoveCircleOutline
            else -> Icons.Rounded.ErrorOutline
        }
        val tint = when (state.kind) {
            StatusKind.OK -> Color(0xFF36D167)
            StatusKind.MISSING -> Color(0xFFF72727)
            else -> Color(0xFFF5A623)
        }
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.defaultColors(color = backgroundColor),
            onClick = ::ensureShizuku,
            showIndication = true,
            pressFeedbackType = PressFeedbackType.Tilt,
        ) {
            Box(modifier = Modifier.fillMaxWidth().heightIn(min = 110.dp)) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = tint,
                    modifier = Modifier
                        .align(Alignment.BottomEnd)
                        .offset(x = 27.dp, y = 31.dp)
                        .size(110.dp),
                )
                Column(
                    modifier = Modifier.padding(start = 16.dp, top = 14.dp, end = 120.dp, bottom = 14.dp),
                ) {
                    Text(text = state.title, fontSize = 22.sp, fontWeight = FontWeight.SemiBold)
                    Spacer(modifier = Modifier.height(1.dp))
                    Text(text = state.summary, fontSize = 15.sp)
                }
            }
        }
    }

    @Composable
    private fun DeviceInfoCard() {
        Card(modifier = Modifier.fillMaxWidth().padding(top = 12.dp), insideMargin = PaddingValues(16.dp)) {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                DeviceInfoItem(stringResource(R.string.info_device), Build.MODEL)
                DeviceInfoItem(stringResource(R.string.info_kernel), System.getProperty("os.version") ?: "?")
                DeviceInfoItem(
                    stringResource(R.string.info_kernelsu),
                    if (ksu.value == "active") stringResource(R.string.info_kernelsu_active) else ksu.value
                )
            }
        }
    }

    @Composable
    private fun DeviceInfoItem(title: String, value: String) {
        androidx.compose.foundation.layout.Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(text = title, fontSize = 14.sp,
                color = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.6f))
            Text(text = value, fontSize = 14.sp, modifier = Modifier.weight(1f),
                textAlign = TextAlign.End)
        }
    }

    @Composable
    private fun RunButton() {
        TextButton(
            text = if (loadingKsu.value) stringResource(R.string.action_running)
            else stringResource(R.string.action_get_root),
            enabled = !loadingKsu.value && !rootFailed.value,
            colors = ButtonDefaults.textButtonColorsPrimary(),
            onClick = ::runRoot,
            modifier = Modifier.fillMaxWidth(),
        )
    }

    @Composable
    private fun LogSheet() {
        OverlayBottomSheet(
            show = logSheetVisible.value || rootFailed.value,
            title = stringResource(R.string.pref_log),
            allowDismiss = !rootFailed.value,
            onDismissRequest = { if (!rootFailed.value) logSheetVisible.value = false },
            startAction = {
                IconButton(onClick = ::copyLog) {
                    Icon(
                        imageVector = MiuixIcons.Copy,
                        contentDescription = stringResource(R.string.action_copy),
                        tint = MiuixTheme.colorScheme.onBackground,
                    )
                }
            },
            endAction = {
                IconButton(
                    enabled = !rootFailed.value,
                    onClick = { if (!rootFailed.value) logSheetVisible.value = false },
                ) {
                    Icon(
                        imageVector = MiuixIcons.Close,
                        contentDescription = stringResource(R.string.action_close)
                    )
                }
            },
            content = {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 240.dp, max = 520.dp)
                        .navigationBarsPadding(),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    LogPanel(
                        lines = logLines.toList(),
                        modifier = Modifier.fillMaxWidth().weight(1f),
                    )
                    if (rootFailed.value) {
                        TextButton(
                            text = stringResource(R.string.action_reboot_retry),
                            colors = ButtonDefaults.textButtonColorsPrimary(),
                            onClick = ::confirmReboot,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                }
            },
        )
    }

    @Composable
    private fun LogPanel(lines: List<String>, modifier: Modifier = Modifier) {
        val listState = rememberLazyListState()
        LaunchedEffect(lines.size) {
            if (lines.isNotEmpty()) listState.scrollToItem(lines.lastIndex)
        }
        Column(
            modifier = modifier
                .clip(androidx.compose.foundation.shape.RoundedCornerShape(8.dp))
                .background(Color(0xFF0B1220))
                .padding(12.dp),
        ) {
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxWidth().fillMaxHeight().padding(top = 8.dp),
            ) {
                items(lines) { line ->
                    Text(
                        text = line.trimEnd('\r', '\n'),
                        color = logColor(line),
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        lineHeight = 16.sp,
                    )
                }
            }
        }
    }

    /**
     * Log level colors, matching GhostLock: "[+]" marks progress, "[-]" a
     * failure and "[!]" a warning; anything else stays neutral.
     */
    private fun logColor(line: String): Color = when {
        line.trimStart().startsWith("[+]") -> Color(0xFF36D167)
        line.trimStart().startsWith("[-]") -> Color(0xFFF72727)
        line.trimStart().startsWith("[!]") -> Color(0xFFF5A623)
        else -> Color(0xFFD1D5DB)
    }

    @Composable
    private fun pageContentPadding(
        scaffoldPadding: PaddingValues,
        top: Dp = 8.dp,
        bottom: Dp = 12.dp,
        horizontalMin: Dp = 12.dp,
    ): PaddingValues {
        val horizontal = horizontalMin
        return PaddingValues(
            start = horizontal,
            end = horizontal,
            top = scaffoldPadding.calculateTopPadding() + top,
            bottom = scaffoldPadding.calculateBottomPadding() + bottom,
        )
    }

    // -------------------------------------------------------------- status

    private enum class StatusKind { OK, MISSING, WARN, FAILED }

    private data class StatusState(val kind: StatusKind, val title: String, val summary: String)

    @Composable
    private fun statusState(): StatusState {
        return when {
            ksu.value == "active" -> StatusState(
                StatusKind.OK,
                stringResource(R.string.status_jailbreak_title),
                stringResource(R.string.status_jailbreak_summary),
            )
            rootOpen.value -> StatusState(
                StatusKind.OK,
                stringResource(R.string.status_root_title),
                stringResource(R.string.status_root_summary),
            )
            shizukuRunning.value && bound.value -> StatusState(
                StatusKind.WARN,
                stringResource(R.string.status_ready_title),
                stringResource(R.string.status_ready_summary),
            )
            else -> StatusState(
                StatusKind.MISSING,
                stringResource(R.string.status_not_connected_title),
                if (shizukuRunning.value) {
                    if (shizukuPermission.value == 0) stringResource(R.string.status_connecting)
                    else stringResource(R.string.status_grant_permission)
                } else {
                    stringResource(R.string.status_start_shizuku)
                },
            )
        }
    }

    private fun refreshDetails() {
        shizukuRunning.value = safePing()
        shizukuPermission.value = safePermission()
        if (service.value != null) {
            Thread {
                try {
                    parseInfo(service.value!!.info())
                } catch (t: Throwable) {
                    Log.i(TAG, "info failed: $t")
                }
            }.start()
        }
    }

    private fun parseInfo(raw: String) {
        for (line in raw.split("\n")) {
            val eq = line.indexOf('=')
            if (eq < 0) continue
            val key = line.substring(0, eq)
            val value = line.substring(eq + 1).trim()
            when (key) {
                "selinux" -> selinux.value = value
                "seccomp" -> seccomp.value = value
                "ksud" -> ksud.value = value
                "ksu" -> ksu.value = value
            }
        }
    }

    // -------------------------------------------------------------- actions

    private fun safePing(): Boolean = try {
        Shizuku.pingBinder()
    } catch (t: Throwable) {
        false
    }

    private fun safePermission(): Int = try {
        Shizuku.checkSelfPermission()
    } catch (t: Throwable) {
        -1
    }

    /** Clicking the top status card drives the device toward a Shizuku
     *  connection: launch the manager when it is not running, ask for the
     *  permission, then bind the user service. */
    private fun ensureShizuku() {
        if (!safePing()) {
            launchShizuku()
            return
        }
        if (safePermission() != 0) {
            try {
                Shizuku.requestPermission(REQUEST_CODE)
                addLog("permission requested")
            } catch (t: Throwable) {
                addLog("request failed: $t")
            }
            return
        }
        if (!bound.value) {
            bindService()
        }
    }

    private fun launchShizuku() {
        try {
            val intent: Intent? = packageManager.getLaunchIntentForPackage(SHIZUKU_PACKAGE)
            if (intent != null) {
                startActivity(intent)
                addLog("opening Shizuku manager")
            } else {
                toast(getString(R.string.toast_shizuku_not_installed))
            }
        } catch (t: Throwable) {
            toast(getString(R.string.toast_shizuku_launch_failed))
            addLog("open Shizuku failed: $t")
        }
    }

    private fun showShizuku() {
        val sb = StringBuilder()
        try {
            sb.append("running: ").append(Shizuku.pingBinder()).append('\n')
            sb.append("permission: ").append(Shizuku.checkSelfPermission()).append('\n')
            sb.append("pre-v11: ").append(Shizuku.isPreV11()).append('\n')
            sb.append("bound: ").append(bound.value)
        } catch (t: Throwable) {
            sb.append("Shizuku not available: ").append(t)
        }
        addLog(sb.toString())
        logSheetVisible.value = true
        if (safePing() && safePermission() != 0) {
            try {
                Shizuku.requestPermission(REQUEST_CODE)
                addLog("permission requested")
            } catch (t: Throwable) {
                addLog("request failed: $t")
            }
        } else if (safePing() && !bound.value) {
            bindService()
        }
    }

    /** Run blocking service calls on the worker while streaming their output. */
    private fun <T> waitingStage(label: String, readOutput: (() -> String)? = null, action: () -> T): T {
        addLog(label)
        if (readOutput == null) return action()
        var previous = ""
        val ticker = Executors.newSingleThreadScheduledExecutor()
        ticker.scheduleAtFixedRate({
            try {
                val output = readOutput.invoke()
                if (output != previous) {
                    val delta = if (output.startsWith(previous)) output.substring(previous.length) else output
                    previous = output
                    if (delta.isNotBlank()) addLog(delta.trimEnd())
                }
            } catch (t: Throwable) { Log.i(TAG, "log poll failed: $t") }
        }, 1, 1, TimeUnit.SECONDS)
        return try { action() } finally { ticker.shutdownNow() }
    }

    private fun runRoot() {
        logSheetVisible.value = true
        if (loadingKsu.value || rootFailed.value) return
        if (!safePing() || safePermission() != 0) {
            addLog(getString(R.string.toast_start_shizuku_first))
            ensureShizuku()
            return
        }
        loadingKsu.value = true
        if (!bound.value) bindService()
        Thread {
            try {
                val s = waitingStage(getString(R.string.toast_connecting)) {
                    val deadline = SystemClock.elapsedRealtime() + 15000
                    var connected: IUserService? = null
                    while (SystemClock.elapsedRealtime() < deadline) {
                        connected = service.value
                        if (connected != null) break
                        Thread.sleep(100)
                    }
                    checkNotNull(connected) { "Shizuku connection timed out" }
                }
                val prepared = waitingStage(getString(R.string.toast_preparing)) {
                    s.install(packageCodePath)
                }
                addLog(prepared)
                check(prepared.startsWith("installed ")) { prepared }
                if (!rootOpen.value) {
                    val out = waitingStage(getString(R.string.log_root_shell), { s.readLog() }) { s.openRoot() }
                    addLog(out)
                    // The service reports "started" even when no uid=0 was observed.
                    fatalMarker(out)?.let { error("$it; reboot before retrying") }
                    check(out.contains("uid=0(root)")) { "Root shell did not report uid=0" }
                    runOnUiThread { rootOpen.value = true }
                }
                if (ksu.value != "active") runKsu(s)
                else addLog(getString(R.string.toast_ksu_loaded))
            } catch (t: Throwable) {
                addLog("Root failed: $t")
                runOnUiThread {
                    rootFailed.value = true
                    logSheetVisible.value = true
                }
            } finally {
                runOnUiThread {
                    loadingKsu.value = false
                    refreshDetails()
                }
            }
        }.start()
    }

    /**
     * Log markers that prove the exploit cannot succeed.  It exits (or the
     * stage script ends) right after printing one of these, so waiting for a
     * success marker such as uid=0(root) or KSU_LOADED is pointless: report
     * the failure and stop instead of polling until the timeout.
     */
    private fun fatalMarker(text: String): String? = when {
        text.contains("base calibration failed") -> "Base calibration failed"
        text.contains("page event ids not found") -> "Tracefs page events not found"
        text.contains("cred leak failed") -> "Cred leak failed"
        text.contains("ksud missing") -> "ksud not found on device"
        text.contains("KSU_MISSING") -> "KernelSU module not loaded"
        else -> null
    }

    private fun runKsu(s: IUserService) {
        var previous = ""
        fun appendOutput(output: String): Boolean {
            if (output == previous) return false
            val delta = if (output.startsWith(previous)) output.substring(previous.length) else output
            previous = output
            if (delta.isNotBlank()) addLog(delta.trimEnd())
            return delta.isNotBlank()
        }
        appendOutput(waitingStage(getString(R.string.action_load_ksu)) { s.runDetached("fake") })
        val start = SystemClock.elapsedRealtime()
        while (SystemClock.elapsedRealtime() - start < 90000) {
            val tail = s.readLog()
            appendOutput(tail)
            if (tail.contains("KSU_LOADED")) {
                parseInfo(s.info())
                addLog(getString(R.string.toast_ksu_loaded))
                return
            }
            check(!tail.contains("selinux write failed")) { "SELinux stage failed; reboot before retrying" }
            check(!tail.contains("parking without reap")) { "Process parked before loading ksud; reboot before retrying" }
            fatalMarker(tail)?.let { error("$it; reboot before retrying") }
            Thread.sleep(1000)
        }
        error("KernelSU timed out after 90s; reboot before retrying")
    }

    private fun confirmReboot() {
        android.app.AlertDialog.Builder(this)
            .setTitle(getString(R.string.dialog_reboot_title))
            .setMessage(getString(R.string.dialog_reboot_message))
            .setPositiveButton(getString(R.string.action_reboot)) { _, _ ->
                val s = service.value
                if (s == null) {
                    toast(getString(R.string.toast_bind_first))
                    return@setPositiveButton
                }
                Thread {
                    try {
                        val result = s.rebootDevice()
                        runOnUiThread { toast(result) }
                    } catch (t: Throwable) {
                        runOnUiThread { toast(getString(R.string.toast_reboot_failed, t)) }
                    }
                }.start()
            }
            .setNegativeButton(getString(R.string.action_cancel), null)
            .show()
    }

    private fun run(label: String, args: String) {
        val s = service.value
        if (s == null) {
            addLog("bind the service first")
            return
        }
        Thread {
            try {
                addLog("[$label]\n" + s.run(args))
            } catch (t: Throwable) {
                addLog("[$label] failed: $t")
            }
        }.start()
    }

    // -------------------------------------------------------------- plumbing

    private fun bindService() {
        try {
            Shizuku.bindUserService(serviceArgs(), connection)
            addLog("binding user service...")
        } catch (t: Throwable) {
            addLog("bind failed: $t")
        }
    }

    private fun serviceArgs(): Shizuku.UserServiceArgs =
        Shizuku.UserServiceArgs(
            ComponentName(packageName, UserService::class.java.name),
        ).daemon(false)
            .processNameSuffix("timer")
            .debuggable(false)
            .version(6)

    private fun copyLog() {
        try {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("TimerRoot", logLines.joinToString("\n")))
            addLog("log copied")
        } catch (t: Throwable) {
            addLog("copy failed: $t")
        }
    }

    private fun addLog(text: String) {
        Log.i(TAG, text.replace('\n', ' '))
        runOnUiThread {
            for (line in text.split("\n")) {
                logLines.add(line)
            }
        }
    }

    private fun toast(text: String) {
        Toast.makeText(this, text, Toast.LENGTH_SHORT).show()
    }
}
