//! RTT mirror of the SSD1306 framebuffer + button input channel.
//!
//! When the `ui-mirror` Cargo feature is active:
//!
//!   * `push()` writes each SSD1306 frame to an RTT up-channel `oled-fb`;
//!     the host binary decodes it and renders a scaled window.
//!   * `try_read_button()` polls an RTT down-channel `btn-in` for single
//!     bytes sent by the host's keyboard handler — same byte protocol as
//!     the existing semihosting bridge: `h/a`=LEFT short, `l/d`=RIGHT
//!     short, `H/A`=LEFT long, `L/D`=RIGHT long.
//!
//! Frame wire format (per frame, 516 bytes):
//!   `0xFB 0x32  len_lo len_hi  <512-byte SSD1306 framebuffer>`
//! The 4-byte header lets the host re-sync if it joins mid-stream.
//!
//! NEVER ship in production. `make prod-check` rejects any build that has
//! the `ui-mirror` feature enabled.

#![cfg(feature = "ui-mirror")]

use rtt_target::{rtt_init, ChannelMode, DownChannel, UpChannel};

/// 512-byte SSD1306 framebuffer + 4-byte header. One channel slot is enough
/// to hold a single frame; `NoBlockSkip` means slow hosts drop frames
/// instead of stalling the MCU during animations.
const UP_CHANNEL_SIZE: usize = 1024;
/// Button bytes are 1 byte each; 16 B absorbs a few key mashes.
const DOWN_CHANNEL_SIZE: usize = 16;

static mut UP_CH: Option<UpChannel> = None;
static mut DOWN_CH: Option<DownChannel> = None;

pub fn init() {
    let channels = rtt_init! {
        up: {
            0: {
                size: UP_CHANNEL_SIZE,
                name: "oled-fb"
            }
        }
        down: {
            0: {
                size: DOWN_CHANNEL_SIZE,
                name: "btn-in"
            }
        }
    };
    let mut up = channels.up.0;
    up.set_mode(ChannelMode::NoBlockSkip);
    let down = channels.down.0;
    // SAFETY: `init()` is called once from `ui::init()` before any other
    // task can call `push()` / `try_read_button()`. Single-core M33; no
    // preemption after init.
    unsafe {
        UP_CH = Some(up);
        DOWN_CH = Some(down);
    }
}

#[allow(static_mut_refs)]
pub fn push(fb: &[u8; 512]) {
    let ch = unsafe {
        match UP_CH.as_mut() {
            Some(c) => c,
            None => return,
        }
    };
    let header = [0xFB, 0x32, (512u16 & 0xFF) as u8, (512u16 >> 8) as u8];
    let _ = ch.write(&header);
    let _ = ch.write(fb);
}

/// Non-blocking read of a single button byte from the host. Returns
/// `None` when the down-channel is empty. Intended to be called in a
/// short polling loop from `Input::wait_button`.
#[allow(static_mut_refs)]
pub fn try_read_button() -> Option<u8> {
    let ch = unsafe { DOWN_CH.as_mut()? };
    let mut buf = [0u8; 1];
    match ch.read(&mut buf) {
        1 => Some(buf[0]),
        _ => None,
    }
}
