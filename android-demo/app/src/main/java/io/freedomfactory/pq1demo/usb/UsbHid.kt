package io.freedomfactory.pq1demo.usb

import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import io.freedomfactory.pq1demo.core.FrameIo
import java.io.Closeable
import java.io.IOException

/**
 * Raw 64-byte HID reports over the PQ1's interrupt endpoints (nonsecure/src/usb/hid.rs:
 * one IN + one OUT interrupt endpoint, no report IDs). No hidraw on Android, so there is
 * no leading report-ID byte to add.
 */
class UsbHidLink private constructor(
    val device: UsbDevice,
    private val conn: UsbDeviceConnection,
    private val intf: UsbInterface,
    private val epIn: UsbEndpoint,
    private val epOut: UsbEndpoint,
) : FrameIo, Closeable {
    @Volatile
    private var closed = false

    override fun write(frame: ByteArray) {
        if (closed) throw IOException("PQ1 disconnected")
        val n = conn.bulkTransfer(epOut, frame, frame.size, 2_000)
        if (n != frame.size) throw IOException("USB write failed ($n)")
    }

    override fun read(timeoutMs: Int): ByteArray? {
        if (closed) throw IOException("PQ1 disconnected")
        val buf = ByteArray(epIn.maxPacketSize.coerceAtLeast(64))
        val n = conn.bulkTransfer(epIn, buf, buf.size, timeoutMs.coerceAtLeast(1))
        if (closed) throw IOException("PQ1 disconnected")
        return if (n > 0) buf.copyOf(n) else null
    }

    override fun close() {
        if (closed) return
        closed = true
        runCatching { conn.releaseInterface(intf) }
        runCatching { conn.close() }
    }

    companion object {
        const val VID = 0x1209
        const val PID = 0x7051

        fun isPq1(d: UsbDevice) = d.vendorId == VID && d.productId == PID

        fun open(mgr: UsbManager, dev: UsbDevice): UsbHidLink {
            for (i in 0 until dev.interfaceCount) {
                val intf = dev.getInterface(i)
                var epIn: UsbEndpoint? = null
                var epOut: UsbEndpoint? = null
                for (e in 0 until intf.endpointCount) {
                    val ep = intf.getEndpoint(e)
                    if (ep.type != UsbConstants.USB_ENDPOINT_XFER_INT) continue
                    if (ep.direction == UsbConstants.USB_DIR_IN) epIn = ep else epOut = ep
                }
                if (epIn == null || epOut == null) continue
                val conn = mgr.openDevice(dev) ?: throw IOException("could not open the USB device")
                if (!conn.claimInterface(intf, true)) {
                    conn.close()
                    throw IOException("could not claim the HID interface")
                }
                return UsbHidLink(dev, conn, intf, epIn, epOut)
            }
            throw IOException("no HID interface with IN+OUT interrupt endpoints")
        }
    }
}
