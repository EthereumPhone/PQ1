package io.freedomfactory.pq1demo.ui

import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.freedomfactory.pq1demo.Active
import io.freedomfactory.pq1demo.Conn
import io.freedomfactory.pq1demo.DemoViewModel
import io.freedomfactory.pq1demo.Phase
import io.freedomfactory.pq1demo.UiState
import io.freedomfactory.pq1demo.core.Expect
import io.freedomfactory.pq1demo.core.Flow
import io.freedomfactory.pq1demo.core.Outcome
import io.freedomfactory.pq1demo.core.hex
import io.freedomfactory.pq1demo.core.hex0x
import io.freedomfactory.pq1demo.core.sha256
import kotlinx.coroutines.delay

/** Accent for a card: the colour of its live state, or null when it is idle. */
fun cardAccent(f: Flow, s: UiState): Color? {
    if (s.queued?.id == f.id) return Pal.amber
    val a = s.active?.takeIf { it.flow.id == f.id } ?: return null
    return when (val p = a.phase) {
        is Phase.Pending -> Pal.amber
        Phase.Sending, is Phase.Waiting -> Pal.green
        is Phase.Done -> verdict(f.expect, p.outcome).color
    }
}

/** The live state of [f], shown inside its card. Nothing when the card is idle. */
@Composable
fun CardStatus(f: Flow, s: UiState, vm: DemoViewModel) {
    if (s.queued?.id == f.id) {
        Line(Pal.amber, "Next. Decline the current request on PQ1 (hold left) to switch.", action = "Cancel" to vm::unqueue)
        return
    }
    val a: Active = s.active?.takeIf { it.flow.id == f.id } ?: return
    when (val p = a.phase) {
        is Phase.Pending -> {
            val what = when (val c = s.conn) {
                Conn.NoDevice -> "Plug in PQ1 and unlock it"
                Conn.NeedsPermission -> "Allow USB access in the Android prompt"
                Conn.Locked -> "Unlock PQ1 with the PIN"
                is Conn.Unlocked -> "Starting…"
                is Conn.Error -> c.message
            }
            p.note?.let { Line(Pal.amber, it) }
            Line(Pal.amber, "$what. Starts by itself.", pulse = true, action = "Cancel" to vm::close)
        }
        Phase.Sending -> Row(Modifier.padding(top = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            CircularProgressIndicator(Modifier.size(14.dp), color = Pal.green, strokeWidth = 2.dp)
            Text("Sending to PQ1…", color = Pal.text, fontSize = 14.sp, modifier = Modifier.padding(start = 10.dp))
        }
        is Phase.Waiting -> {
            var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
            LaunchedEffect(p) { while (true) { now = System.currentTimeMillis(); delay(500) } }
            val secs = ((now - p.sinceMs) / 1000).coerceAtLeast(0)
            val hint = when (f.expect) {
                Expect.SIGN, Expect.CONFIRM -> "Look at PQ1. Both buttons sign, hold left declines."
                Expect.REFUSE -> "Look at PQ1. It should refuse."
                Expect.LOCK -> "Locking…"
            }
            Line(Pal.green, "$hint  ${secs}s", pulse = true, action = "Stop" to vm::stopWaiting)
        }
        is Phase.Done -> Result(f, p.outcome)
    }
}

@Composable
private fun Line(color: Color, text: String, pulse: Boolean = false, action: Pair<String, () -> Unit>? = null) {
    Row(Modifier.fillMaxWidth().padding(top = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        Dot(color, pulse)
        Text(text, color = Pal.text, fontSize = 14.sp, lineHeight = 19.sp, modifier = Modifier.weight(1f).padding(start = 10.dp))
        action?.let { (label, onClick) ->
            Text(
                label, color = Pal.muted, fontSize = 13.sp,
                modifier = Modifier.clip(CircleShape).clickable(onClick = onClick).padding(horizontal = 8.dp, vertical = 4.dp),
            )
        }
    }
}

@Composable
private fun Dot(color: Color, pulse: Boolean) {
    val alpha = if (pulse) {
        val t = rememberInfiniteTransition(label = "dot")
        t.animateFloat(1f, 0.25f, infiniteRepeatable(tween(700), RepeatMode.Reverse), label = "a").value
    } else 1f
    Box(Modifier.size(9.dp).alpha(alpha).clip(CircleShape).background(color))
}

private data class Verdict(val color: Color, val mark: String, val title: String, val body: String)

private fun verdict(expect: Expect, o: Outcome): Verdict = when (o) {
    is Outcome.Signed ->
        if (expect == Expect.REFUSE) Verdict(Pal.red, "!", "PQ1 signed", "This should have been refused. Check the firmware build.")
        else Verdict(Pal.green, "✓", "Signed", "SPHINCS+ C10 post-quantum signature, made and verified inside PQ1.")
    is Outcome.Refused ->
        if (expect == Expect.REFUSE) Verdict(Pal.green, "✓", "Attack blocked", "PQ1 saw a DELEGATECALL to unknown code and refused. No signature left the device.")
        else Verdict(Pal.amber, "!", "PQ1 refused (SW %04X)".format(o.sw), "A firmware gate refused it. The device screen says which.")
    Outcome.Declined -> Verdict(Pal.muted, "✕", "Declined on PQ1", "Nothing was signed.")
    Outcome.IdleWiped -> Verdict(Pal.amber, "!", "PQ1 locked itself", "The 120 s idle timer fired while waiting.")
    Outcome.NotReady -> Verdict(Pal.amber, "!", "PQ1 not ready", "Locked or busy. Tap to try again.")
    is Outcome.Confirmed -> Verdict(Pal.green, "✓", "Address confirmed", chunk(o.address.hex0x()))
    Outcome.Locked -> Verdict(Pal.green, "✓", "PQ1 locked", "Secrets wiped. Enter the PIN to continue.")
    Outcome.Abandoned -> Verdict(Pal.muted, "·", "Stopped waiting", "If PQ1 still shows it, decline there (hold left).")
    is Outcome.Failed -> Verdict(Pal.red, "!", "Failed", o.message)
}

@Composable
private fun Result(f: Flow, o: Outcome) {
    val v = verdict(f.expect, o)
    Column(Modifier.padding(top = 10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(v.mark, color = v.color, fontSize = 18.sp, fontWeight = FontWeight.Bold)
            Text(v.title, color = v.color, fontSize = 16.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(start = 8.dp))
        }
        Text(v.body, color = Pal.text, fontSize = 13.sp, lineHeight = 18.sp, modifier = Modifier.padding(top = 2.dp))
        if (o is Outcome.Signed) {
            Text(
                "%,d B signature · sha256 %s…".format(o.signature.size, sha256(o.signature).hex().take(12)),
                color = Pal.muted, fontFamily = Mono, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp),
            )
        }
        Text("Tap to run again", color = Pal.muted, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp))
    }
}
