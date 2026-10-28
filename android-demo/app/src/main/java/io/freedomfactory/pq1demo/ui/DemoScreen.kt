package io.freedomfactory.pq1demo.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.freedomfactory.pq1demo.Conn
import io.freedomfactory.pq1demo.DemoViewModel
import io.freedomfactory.pq1demo.UiState
import io.freedomfactory.pq1demo.core.Expect
import io.freedomfactory.pq1demo.core.FieldKind
import io.freedomfactory.pq1demo.core.Flow
import io.freedomfactory.pq1demo.core.Flows
import io.freedomfactory.pq1demo.core.Wire
import io.freedomfactory.pq1demo.core.addr
import io.freedomfactory.pq1demo.core.hex0x

@Composable
fun DemoScreen(vm: DemoViewModel) {
    val s by vm.state.collectAsStateWithLifecycle()
    var open by remember { mutableStateOf<Flow?>(null) }
    var settings by remember { mutableStateOf(false) }

    Box(Modifier.fillMaxSize().background(Pal.bg)) {
        LazyColumn(
            Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item { Header(s.conn) { settings = true } }
            item { ConnCard(s, vm) }
            for ((group, flows) in Flows.all.groupBy { it.group }) {
                item { SectionLabel(group) }
                items(flows, key = { it.id }) { f -> FlowCard(f, s, vm, onEdit = { open = f }) }
            }
            item { SectionLabel("Device") }
            items(Flows.device, key = { it.id }) { f -> FlowCard(f, s, vm, onEdit = null) }
            item {
                Text(
                    "Tap a demo to run it; it starts once PQ1 is unlocked. Long-press to edit amounts. Nothing is broadcast.",
                    color = Pal.muted, fontSize = 12.sp, modifier = Modifier.padding(top = 12.dp),
                )
            }
        }

        open?.let { f -> FlowSheet(f, s, vm, onDismiss = { open = null }) { open = null; vm.demo(f) } }
        if (settings) SettingsSheet(s, vm) { settings = false }
    }
}

@Composable
private fun Header(conn: Conn, onSettings: () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(bottom = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Text("PQ1", color = Pal.text, fontSize = 28.sp, fontWeight = FontWeight.Black, letterSpacing = (-0.5).sp)
        Text("  demo", color = Pal.muted, fontSize = 18.sp, modifier = Modifier.padding(top = 6.dp))
        Spacer(Modifier.weight(1f))
        StatusPill(conn)
        TextButton(onClick = onSettings) { Text("⋯", color = Pal.muted, fontSize = 22.sp) }
    }
}

@Composable
private fun StatusPill(conn: Conn) {
    val (label, color) = when (conn) {
        Conn.NoDevice -> "Not connected" to Pal.muted
        Conn.NeedsPermission -> "USB access" to Pal.amber
        Conn.Locked -> "Locked" to Pal.amber
        is Conn.Unlocked -> "Unlocked" to Pal.green
        is Conn.Error -> "Error" to Pal.red
    }
    Row(
        Modifier.clip(CircleShape).background(Pal.surface).padding(horizontal = 10.dp, vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(7.dp).clip(CircleShape).background(color))
        Text(label, color = Pal.text, fontSize = 12.sp, modifier = Modifier.padding(start = 6.dp))
    }
}

@Composable
private fun ConnCard(s: UiState, vm: DemoViewModel) {
    Card {
        when (val c = s.conn) {
            Conn.NoDevice -> {
                Big("Plug in PQ1")
                Body("USB-C to USB-C. PQ1 appears over USB once it is unlocked with its PIN.")
            }
            Conn.NeedsPermission -> {
                Big("Allow USB access")
                Body("Android needs permission to talk to PQ1. Tick \"always\" to skip this next time.")
                Spacer(Modifier.height(10.dp))
                PrimaryButton("Grant access") { vm.requestPermission() }
            }
            Conn.Locked -> {
                Big("Unlock PQ1")
                Body("Enter the PIN on the device. Idle for 120 s, it locks itself again.")
            }
            is Conn.Unlocked -> {
                Text("SMART WALLET", color = Pal.muted, fontSize = 11.sp, letterSpacing = 1.2.sp)
                Spacer(Modifier.height(6.dp))
                val w = s.wallet
                if (w == null) {
                    Body("Deriving the post-quantum keys on PQ1…")
                } else {
                    Text(chunk(w), color = Pal.text, fontFamily = Mono, fontSize = 15.sp, lineHeight = 21.sp)
                    Spacer(Modifier.height(6.dp))
                    Body("Same address on every chain. Controlled only by SPHINCS+ keys inside PQ1.")
                }
                c.attempts?.let {
                    Spacer(Modifier.height(4.dp))
                    Text("PIN attempts left: $it", color = Pal.muted, fontSize = 12.sp)
                }
            }
            is Conn.Error -> {
                Big("USB problem")
                Body(c.message)
            }
        }
    }
}

/** "0x1234 5678 …" groups of four, easy to compare with the device screen. */
fun chunk(a: String): String {
    val h = a.removePrefix("0x")
    return "0x " + h.chunked(4).joinToString(" ")
}

@Composable
private fun SectionLabel(t: String) =
    Text(t.uppercase(), color = Pal.muted, fontSize = 11.sp, letterSpacing = 1.2.sp, modifier = Modifier.padding(top = 14.dp, bottom = 2.dp))

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun FlowCard(f: Flow, s: UiState, vm: DemoViewModel, onEdit: (() -> Unit)?) {
    val accent = cardAccent(f, s)
    val border = accent ?: if (f.expect == Expect.REFUSE) Pal.red.copy(alpha = 0.35f) else Pal.line
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(Pal.surface)
            .border(if (accent != null) 2.dp else 1.dp, border, RoundedCornerShape(14.dp))
            .combinedClickable(onClick = { vm.demo(f) }, onLongClick = onEdit).padding(14.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(f.title, color = Pal.text, fontSize = 16.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
            if (f.chain.isNotEmpty()) Chip(f.chain, Pal.muted)
        }
        if (accent == null) {
            Spacer(Modifier.height(4.dp))
            Text(f.blurb, color = Pal.muted, fontSize = 13.sp, lineHeight = 18.sp, maxLines = 3, overflow = TextOverflow.Ellipsis)
            if (f.expect == Expect.REFUSE) {
                Spacer(Modifier.height(8.dp))
                Chip("PQ1 should refuse", Pal.red)
            }
        }
        CardStatus(f, s, vm)
    }
}

@Composable
fun Chip(t: String, color: Color) {
    Text(
        t, color = color, fontSize = 11.sp,
        modifier = Modifier.clip(CircleShape).border(1.dp, color.copy(alpha = 0.4f), CircleShape).padding(horizontal = 8.dp, vertical = 2.dp),
    )
}

@Composable
fun Card(content: @Composable () -> Unit) {
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(Pal.surface)
            .border(1.dp, Pal.line, RoundedCornerShape(16.dp)).padding(16.dp)
    ) { content() }
}

@Composable
fun Big(t: String) = Text(t, color = Pal.text, fontSize = 20.sp, fontWeight = FontWeight.Bold)

@Composable
fun Body(t: String) = Text(t, color = Pal.muted, fontSize = 14.sp, lineHeight = 20.sp, modifier = Modifier.padding(top = 4.dp))

@Composable
fun PrimaryButton(t: String, enabled: Boolean = true, onClick: () -> Unit) {
    Button(
        onClick = onClick, enabled = enabled,
        modifier = Modifier.fillMaxWidth().height(52.dp),
        shape = RoundedCornerShape(12.dp),
        colors = ButtonDefaults.buttonColors(containerColor = Pal.text, contentColor = Pal.bg, disabledContainerColor = Pal.surface2, disabledContentColor = Pal.muted),
    ) { Text(t, fontSize = 16.sp, fontWeight = FontWeight.SemiBold) }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FlowSheet(f: Flow, s: UiState, vm: DemoViewModel, onDismiss: () -> Unit, onSend: () -> Unit) {
    val values = s.values[f.id] ?: emptyMap()
    val error = f.validate(values)
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true), containerColor = Pal.surface) {
        Column(Modifier.padding(horizontal = 20.dp).padding(bottom = 24.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(f.title, color = Pal.text, fontSize = 22.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                if (f.chain.isNotEmpty()) Chip(f.chain, Pal.muted)
            }
            Body(f.blurb)
            if (f.fields.isNotEmpty()) {
                Spacer(Modifier.height(14.dp))
                for (fld in f.fields) {
                    OutlinedTextField(
                        value = values[fld.key] ?: fld.default,
                        onValueChange = { vm.setValue(f, fld.key, it) },
                        label = { Text(fld.label) },
                        suffix = if (fld.suffix.isNotEmpty()) ({ Text(fld.suffix, color = Pal.muted) }) else null,
                        singleLine = true,
                        textStyle = androidx.compose.ui.text.TextStyle(fontFamily = if (fld.kind == FieldKind.ADDRESS) Mono else null, fontSize = 15.sp, color = Pal.text),
                        keyboardOptions = KeyboardOptions(keyboardType = if (fld.kind == FieldKind.AMOUNT) KeyboardType.Decimal else KeyboardType.Ascii),
                        colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = Pal.text, unfocusedBorderColor = Pal.line, focusedLabelColor = Pal.text),
                        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                    )
                }
                if (values.isNotEmpty()) TextButton(onClick = { vm.resetValues(f) }) { Text("Reset to demo values", color = Pal.muted) }
                error?.let { Text(it, color = Pal.red, fontSize = 13.sp) }
            }
            Spacer(Modifier.height(14.dp))
            Text("ON THE PQ1 SCREEN", color = Pal.muted, fontSize = 11.sp, letterSpacing = 1.2.sp)
            for (line in f.onDevice) {
                Row(Modifier.padding(top = 6.dp)) {
                    Text("›", color = Pal.green, modifier = Modifier.width(16.dp))
                    Text(line, color = Pal.text, fontSize = 14.sp, lineHeight = 19.sp)
                }
            }
            Spacer(Modifier.height(20.dp))
            PrimaryButton("Demo", enabled = error == null, onClick = onSend)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsSheet(s: UiState, vm: DemoViewModel, onDismiss: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = Pal.surface) {
        Column(Modifier.padding(horizontal = 20.dp).padding(bottom = 24.dp)) {
            Big("Settings")
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = s.safe, onValueChange = vm::setSafe, label = { Text("Safe address (Safe flows)") }, singleLine = true,
                textStyle = androidx.compose.ui.text.TextStyle(fontFamily = Mono, fontSize = 14.sp, color = Pal.text),
                isError = runCatching { addr(s.safe) }.isFailure,
                colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = Pal.text, unfocusedBorderColor = Pal.line, focusedLabelColor = Pal.text),
                modifier = Modifier.fillMaxWidth(),
            )
            TextButton(onClick = { vm.setSafe(Wire.DEMO_SAFE.hex0x()) }) {
                Text("Use demo Safe 0x5afe…0001", color = Pal.muted)
            }
            Spacer(Modifier.height(8.dp))
            Body("Requests sent: ${s.take}. It is the UserOp nonce, and the Safe nonce is 17 + it.")
            TextButton(onClick = vm::resetTake) { Text("Reset counter", color = Pal.muted) }
            Spacer(Modifier.height(8.dp))
            Body("Token proofs are bundled from tools/companion-stub/erc20_db.bin. If the firmware's ERC20_DB_ROOT changes, re-run android-demo/tools/gen_assets.py and rebuild.")
        }
    }
}
