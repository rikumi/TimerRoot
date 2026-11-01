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
    private val loadingKsu = mutableStateOf(false)
    private val loadingSecs = mutableStateOf(0L)
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
        }
        LogSheet()
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
            item(key = "ksu") {
                TextButton(
                    text = if (loadingKsu.value) {
                        stringResource(R.string.action_loading_ksu, loadingSecs.value)
                    } else {
                        stringResource(R.string.action_load_ksu)
                    },
                    enabled = !loadingKsu.value,
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                    onClick = ::confirmKsu,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            item(key = "stop") {
                TextButton(
                    text = stringResource(R.string.action_stop),
                    enabled = rootOpen.value,
                    colors = ButtonDefaults.textButtonColors(),
                    onClick = ::stopRoot,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            item(key = "reboot") {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    onClick = ::confirmReboot,
                    showIndication = true,
                    pressFeedbackType = PressFeedbackType.Tilt,
                ) {
                    ArrowPreference(
                        title = stringResource(R.string.action_reboot),
                        summary = stringResource(R.string.summary_reboot),
                        onClick = ::confirmReboot,
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
                    title = stringResource(R.string.pref_prepare),
                    summary = stringResource(R.string.pref_prepare_summary),
                    onClick = ::prepare,
                )
                ArrowPreference(
                    title = stringResource(R.string.pref_diagnose),
                    summary = stringResource(R.string.pref_diagnose_summary),
                    onClick = { run("ids", "ids") },
                )
                ArrowPreference(
                    title = stringResource(R.string.pref_log),
                    summary = stringResource(R.string.pref_log_summary),
                    onClick = { logSheetVisible.value = true },
                )
            }
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
                verticalArrangement = Arrangement.spacedBy(20.dp),
            ) {
                DeviceInfoItem(stringResource(R.string.info_device), Build.MODEL + " / " + Build.PRODUCT)
                DeviceInfoItem(stringResource(R.string.info_kernel), System.getProperty("os.version") ?: "?")
                DeviceInfoItem(stringResource(R.string.info_ksud), ksud.value)
                DeviceInfoItem(
                    stringResource(R.string.info_kernelsu),
                    if (ksu.value == "active") stringResource(R.string.info_kernelsu_active) else ksu.value
                )
                DeviceInfoItem(stringResource(R.string.info_selinux), selinux.value)
                DeviceInfoItem(stringResource(R.string.info_seccomp), seccomp.value)
            }
        }
    }

    @Composable
    private fun DeviceInfoItem(title: String, value: String) {
        Column {
            Text(
                text = title,
                fontSize = 18.sp,
                fontWeight = FontWeight.Medium,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Text(
                text = value,
                modifier = Modifier.padding(top = 2.dp),
                fontSize = 14.sp,
                color = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.68f),
            )
        }
    }

    @Composable
    private fun RunButton() {
        TextButton(
            text = if (loadingKsu.value) stringResource(R.string.action_running)
            else stringResource(R.string.action_get_root),
            enabled = bound.value && !loadingKsu.value,
            colors = ButtonDefaults.textButtonColorsPrimary(),
            onClick = ::confirmRoot,
            modifier = Modifier.fillMaxWidth(),
        )
    }

    @Composable
    private fun LogSheet() {
        OverlayBottomSheet(
            show = logSheetVisible.value,
            title = stringResource(R.string.pref_log),
            allowDismiss = true,
            onDismissRequest = { logSheetVisible.value = false },
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
                IconButton(onClick = { logSheetVisible.value = false }) {
                    Icon(
                        imageVector = MiuixIcons.Close,
                        contentDescription = stringResource(R.string.action_close)
                    )
                }
            },
            content = {
                LogPanel(
                    lines = logLines.toList(),
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 240.dp, max = 520.dp)
                        .navigationBarsPadding(),
                )
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
                        color = Color(0xFFD1D5DB),
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        lineHeight = 16.sp,
                    )
                }
            }
        }
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

    private fun prepare() {
        if (!safePing()) {
            toast(getString(R.string.toast_start_shizuku_first))
            showShizuku()
            return
        }
        if (service.value == null) {
            bindService()
            toast(getString(R.string.toast_connecting))
            return
        }
        toast(getString(R.string.toast_preparing))
        Thread {
            try {
                val result = service.value!!.install(packageCodePath)
                addLog(result)
                runOnUiThread {
                    toast(result)
                    refreshDetails()
                }
            } catch (t: Throwable) {
                addLog("prepare failed: $t")
                runOnUiThread { toast(getString(R.string.toast_prepare_failed, t)) }
            }
        }.start()
    }

    private fun confirmRoot() {
        android.app.AlertDialog.Builder(this)
            .setTitle(getString(R.string.dialog_root_title))
            .setMessage(getString(R.string.dialog_root_message))
            .setPositiveButton(getString(R.string.action_run)) { _, _ -> runRoot() }
            .setNegativeButton(getString(R.string.action_cancel), null)
            .show()
    }

    private fun runRoot() {
        val s = service.value
        if (s == null) {
            addLog("bind the service first")
            return
        }
        Thread {
            try {
                val out = s.openRoot()
                rootOpen.value = out.contains("uid=0(root)") || out.contains("started")
                addLog(out)
                if (rootOpen.value && ksu.value != "active") {
                    addLog("root shell ready - loading KernelSU...")
                    runKsu()
                }
            } catch (t: Throwable) {
                addLog("root failed: $t")
            }
        }.start()
    }

    private fun confirmKsu() {
        android.app.AlertDialog.Builder(this)
            .setTitle(getString(R.string.dialog_ksu_title))
            .setMessage(getString(R.string.dialog_ksu_message))
            .setPositiveButton(getString(R.string.action_run)) { _, _ -> runKsu() }
            .setNegativeButton(getString(R.string.action_cancel), null)
            .show()
    }

    private fun runKsu() {
        val s = service.value
        if (s == null) {
            addLog("bind the service first")
            return
        }
        loadingKsu.value = true
        loadingSecs.value = 0
        Thread {
            try {
                addLog(s.runDetached("fake"))
                val start = System.currentTimeMillis()
                var loaded = false
                var failure: String? = null
                while (System.currentTimeMillis() - start < 90000) {
                    Thread.sleep(1000)
                    loadingSecs.value = (System.currentTimeMillis() - start) / 1000
                    val tail = s.readLog()
                    if (tail.contains("KSU_LOADED")) {
                        loaded = true
                        break
                    }
                    if (tail.contains("selinux write failed")) {
                        failure = "the selinux stage missed its race"
                        break
                    }
                    if (tail.contains("parking without reap")) {
                        failure = "the exploit parked before loading ksud"
                        break
                    }
                }
                if (!loaded && failure == null) failure = "timed out after 90s"
                if (loaded) parseInfo(s.info())
                addLog(s.readLog())
                loadingKsu.value = false
                runOnUiThread {
                    if (loaded) {
                        toast(getString(R.string.toast_ksu_loaded))
                        refreshDetails()
                    } else {
                        toast(getString(R.string.toast_ksu_failed, failure ?: "unknown"))
                        addLog("KernelSU failed: $failure - parked processes remain; reboot to clean up")
                    }
                }
            } catch (t: Throwable) {
                loadingKsu.value = false
                addLog("ksu failed: $t")
            }
        }.start()
    }

    private fun stopRoot() {
        val s = service.value ?: return
        Thread {
            try {
                addLog(s.closeRoot())
                rootOpen.value = false
            } catch (t: Throwable) {
                addLog("stop failed: $t")
            }
        }.start()
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
            .version(5)

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
