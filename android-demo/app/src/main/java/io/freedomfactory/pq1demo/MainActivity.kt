package io.freedomfactory.pq1demo

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.core.content.ContextCompat
import io.freedomfactory.pq1demo.ui.DemoScreen
import io.freedomfactory.pq1demo.ui.Pq1Theme

class MainActivity : ComponentActivity() {
    private val vm: DemoViewModel by viewModels()

    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            when (intent.action) {
                UsbManager.ACTION_USB_DEVICE_DETACHED -> vm.onDetached(intent.usbDevice())
                UsbManager.ACTION_USB_DEVICE_ATTACHED -> vm.onAttached()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // A demo is held up to a camera: keep the screen on.
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        ContextCompat.registerReceiver(
            this, usbReceiver,
            IntentFilter().apply {
                addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
                addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
            },
            ContextCompat.RECEIVER_EXPORTED, // system broadcasts
        )
        setContent { Pq1Theme { DemoScreen(vm) } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // Launched (or re-launched) by the PQ1 attach filter: permission is already granted.
        if (intent.action == UsbManager.ACTION_USB_DEVICE_ATTACHED) vm.onAttached()
    }

    override fun onDestroy() {
        unregisterReceiver(usbReceiver)
        super.onDestroy()
    }
}

@Suppress("DEPRECATION")
private fun Intent.usbDevice(): UsbDevice? =
    if (Build.VERSION.SDK_INT >= 33) getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
    else getParcelableExtra(UsbManager.EXTRA_DEVICE)
