package io.freedomfactory.pq1demo

import android.app.Application
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.freedomfactory.pq1demo.core.DeviceTimeout
import io.freedomfactory.pq1demo.core.Flow
import io.freedomfactory.pq1demo.core.FlowCtx
import io.freedomfactory.pq1demo.core.Outcome
import io.freedomfactory.pq1demo.core.Pq1
import io.freedomfactory.pq1demo.core.ProofSource
import io.freedomfactory.pq1demo.core.RequestKind
import io.freedomfactory.pq1demo.core.Wire
import io.freedomfactory.pq1demo.core.addr
import io.freedomfactory.pq1demo.core.hex
import io.freedomfactory.pq1demo.core.hex0x
import io.freedomfactory.pq1demo.usb.UsbHidLink
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.IOException

sealed interface Conn {
    data object NoDevice : Conn
    data object NeedsPermission : Conn
    data object Locked : Conn          // enumerated, but locked or not answering
    data class Unlocked(val attempts: Int?) : Conn
    data class Error(val message: String) : Conn
}

sealed interface Phase {
    /** Chosen, waiting for an unlocked PQ1; [note] says why it is (back) here. */
    data class Pending(val note: String? = null) : Phase
    data object Sending : Phase
    data class Waiting(val sinceMs: Long) : Phase
    data class Done(val outcome: Outcome) : Phase
}

data class Active(val flow: Flow, val phase: Phase)

data class UiState(
    val conn: Conn = Conn.NoDevice,
    val wallet: String? = null,
    val active: Active? = null,
    /** Tapped while another request was on the device; starts once that one is answered. */
    val queued: Flow? = null,
    val take: Long = 0,
    val safe: String = Wire.DEMO_SAFE.hex0x(),
    val values: Map<String, Map<String, String>> = emptyMap(),
)

class DemoViewModel(app: Application) : AndroidViewModel(app) {
    companion object {
        const val ACTION_USB_PERMISSION = "io.freedomfactory.pq1demo.USB_PERMISSION"
        const val CONFIRM_TIMEOUT_MS = 300_000L
    }

    private val usb = app.getSystemService(Context.USB_SERVICE) as UsbManager
    private val prefs = app.getSharedPreferences("pq1demo", Context.MODE_PRIVATE)
    private val io = Mutex()
    private var link: UsbHidLink? = null
    private var permissionAsked: String? = null
    @Volatile private var cancel = false
    @Volatile private var closing = false
    private val wake = Channel<Unit>(Channel.CONFLATED)

    private val _state = MutableStateFlow(
        UiState(
            take = prefs.getLong("take", 0),
            safe = prefs.getString("safe", null) ?: Wire.DEMO_SAFE.hex0x(),
        )
    )
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val proofs = ProofSource { chain, token ->
        try {
            app.assets.open("erc20/${chain}_${token.hex()}.bin").use { it.readBytes() }
        } catch (e: IOException) {
            throw IllegalStateException("no ERC-20 proof bundled for ${token.hex0x()} on chain $chain")
        }
    }

    init {
        viewModelScope.launch(Dispatchers.IO) {
            // One loop owns the USB link: poll the device, and start the chosen demo
            // as soon as PQ1 is unlocked. A tap wakes it early.
            while (true) {
                runCatching { tick() }
                val a = _state.value.active
                if (a != null && a.phase is Phase.Pending && _state.value.conn is Conn.Unlocked) {
                    execute(a.flow)
                    continue
                }
                withTimeoutOrNull(1_000) { wake.receive() }
            }
        }
    }

    // ── connection polling ──

    private suspend fun tick() {
        val l = link
        if (l == null) {
            val dev = usb.deviceList.values.firstOrNull(UsbHidLink::isPq1)
            when {
                dev == null -> setConn(Conn.NoDevice)
                !usb.hasPermission(dev) -> {
                    setConn(Conn.NeedsPermission)
                    if (permissionAsked != dev.deviceName) {
                        permissionAsked = dev.deviceName
                        requestPermission(dev)
                    }
                }
                else -> try {
                    link = UsbHidLink.open(usb, dev)
                    poll()
                } catch (e: IOException) {
                    setConn(Conn.Error(e.message ?: "USB error"))
                }
            }
        } else {
            poll()
        }
    }

    private suspend fun poll() {
        val l = link ?: return
        io.withLock {
            try {
                val st = Pq1(l).status()
                if (!st.unlocked) {
                    setConn(Conn.Locked)
                    return
                }
                setConn(Conn.Unlocked(st.remainingAttempts))
                if (_state.value.wallet == null) {
                    val a = Pq1(l).walletAddress()
                    _state.update { it.copy(wallet = a.hex0x()) }
                }
            } catch (e: DeviceTimeout) {
                setConn(Conn.Locked)   // enumerated but silent: relocked, PIN prompt on screen
            } catch (e: IOException) {
                drop()
            }
        }
    }

    fun requestPermission(dev: UsbDevice? = usb.deviceList.values.firstOrNull(UsbHidLink::isPq1)) {
        dev ?: return
        val app = getApplication<Application>()
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0
        val pi = PendingIntent.getBroadcast(app, 0, Intent(ACTION_USB_PERMISSION).setPackage(app.packageName), flags)
        usb.requestPermission(dev, pi)
    }

    fun onDetached(dev: UsbDevice?) {
        if (dev == null || link?.device?.deviceName == dev.deviceName) drop()
    }

    fun onAttached() {
        permissionAsked = null
    }

    private fun drop() {
        link?.close()
        link = null
        _state.update { it.copy(conn = Conn.NoDevice, wallet = null) }
    }

    private fun setConn(c: Conn) = _state.update { it.copy(conn = c) }

    // ── flows ──

    fun setValue(flow: Flow, key: String, value: String) = _state.update {
        it.copy(values = it.values + (flow.id to ((it.values[flow.id] ?: emptyMap()) + (key to value))))
    }

    fun resetValues(flow: Flow) = _state.update { it.copy(values = it.values - flow.id) }

    fun setSafe(s: String) {
        _state.update { it.copy(safe = s) }
        if (runCatching { addr(s) }.isSuccess) prefs.edit().putString("safe", s.trim()).apply()
    }

    fun resetTake() {
        _state.update { it.copy(take = 0) }
        prefs.edit().putLong("take", 0).apply()
    }

    private fun inFlight(a: Active?) = a != null && (a.phase is Phase.Sending || a.phase is Phase.Waiting)

    /**
     * Demo [flow]: it starts as soon as PQ1 is connected and unlocked. While another request is
     * on the device's screen the new one is queued; it starts once that one is answered
     * (declining on PQ1 is the way to switch).
     */
    fun demo(flow: Flow) {
        val a = _state.value.active
        if (inFlight(a)) {
            if (a!!.flow.id != flow.id) _state.update { it.copy(queued = flow) }
            return
        }
        closing = false
        _state.update { it.copy(active = Active(flow, Phase.Pending()), queued = null) }
        wake.trySend(Unit)
    }

    fun unqueue() = _state.update { it.copy(queued = null) }

    fun stopWaiting() {
        cancel = true
    }

    /** Leave the demo stage; abandons a request still waiting on the device. */
    fun close() {
        if (inFlight(_state.value.active)) {
            closing = true
            cancel = true
        }
        _state.update { it.copy(active = null, queued = null) }
    }

    private suspend fun execute(flow: Flow) {
        val l = link ?: return
        val s = _state.value
        cancel = false
        _state.update { it.copy(active = Active(flow, Phase.Sending)) }
        val outcome = io.withLock {
            try {
                val pq1 = Pq1(l)
                val sender = s.wallet?.let(::addr) ?: pq1.walletAddress()
                val safe = runCatching { addr(s.safe) }.getOrDefault(Wire.DEMO_SAFE)
                val ctx = FlowCtx(sender, s.take, System.currentTimeMillis() / 1000 + 3600, safe, proofs)
                val req = flow.build(ctx, s.values[flow.id] ?: emptyMap())
                if (req.kind == RequestKind.USEROP) bumpTake()
                pq1.run(req, CONFIRM_TIMEOUT_MS, { cancel }) {
                    if (!closing) _state.update { it.copy(active = Active(flow, Phase.Waiting(System.currentTimeMillis()))) }
                }
            } catch (e: Exception) {
                Outcome.Failed(e.message ?: e.javaClass.simpleName)
            }
        }
        if (outcome is Outcome.Locked || outcome is Outcome.IdleWiped) setConn(Conn.Locked)
        val next = _state.value.queued
        // PQ1 relocked or was unplugged mid-request: wait for the next unlock and run it again.
        val retry = when {
            outcome is Outcome.IdleWiped -> "PQ1 locked itself while waiting (idle timeout)."
            outcome is Outcome.Failed && link == null -> "PQ1 was disconnected."
            else -> null
        }
        _state.update {
            when {
                closing -> it.copy(active = null, queued = null)
                // PQ1 may still be showing the abandoned request and not reading USB: don't
                // push the queued one at it; the user taps again once PQ1 is back.
                outcome is Outcome.Abandoned -> it.copy(active = Active(flow, Phase.Done(outcome)), queued = null)
                next != null -> it.copy(active = Active(next, Phase.Pending()), queued = null)
                retry != null -> it.copy(active = Active(flow, Phase.Pending(retry)))
                else -> it.copy(active = Active(flow, Phase.Done(outcome)))
            }
        }
        closing = false
    }

    private fun bumpTake() {
        val t = _state.value.take + 1
        _state.update { it.copy(take = t) }
        prefs.edit().putLong("take", t).apply()
    }

    override fun onCleared() {
        link?.close()
    }
}
