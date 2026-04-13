//! Host-side viewer for the SSD1306 framebuffer streamed via RTT.
//!
//! Flashing is left to the `probe-rs` CLI (the STM32U585 secure-flash
//! alias `0x0C000000` is only known to the CLI's chip lookup, not to the
//! `flashing::download_file` library call). This tool:
//!
//!   1. Attaches to the ST-LINK probe via probe-rs (as a library)
//!   2. Resets the target and starts it
//!   3. Attaches to the `oled-fb` RTT up-channel
//!   4. Decodes framed frames and renders them in a scaled window
//!      (default) or as Braille glyphs on stdout (`--terminal`)
//!
//! Wire format (must match `secure/src/ui/mirror.rs`):
//!   `0xFB 0x32  len_lo len_hi  <512-byte SSD1306 framebuffer>`
//!
//! Usage:
//!   probe-rs download --chip STM32U585AIIx <elf>
//!   oled-mirror --chip STM32U585AIIx --rtt-addr 0x30002e48

use anyhow::{anyhow, Context, Result};
use probe_rs::{
    probe::list::Lister,
    rtt::{Rtt, ScanRegion},
    MemoryInterface, Permissions, RegisterId, Session,
};
use std::{
    io::Write,
    num::NonZeroU32,
    rc::Rc,
    time::{Duration, Instant},
};
use winit::{
    dpi::LogicalSize,
    event::{ElementState, Event, KeyEvent, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    keyboard::{Key, NamedKey},
    window::WindowBuilder,
};

const SCREEN_W: usize = 128;
const SCREEN_H: usize = 32;
const FB_BYTES: usize = SCREEN_W * SCREEN_H / 8; // 512
const HEADER: [u8; 2] = [0xFB, 0x32];

// softbuffer uses 0x00RRGGBB — top byte is ignored. OLED-blue on
// near-black roughly matches a real 0.91" SSD1306 module.
const COLOR_ON: u32 = 0x0055AAFF;
const COLOR_OFF: u32 = 0x00101018;

struct Args {
    chip: String,
    rtt_addr: Option<u64>,
    terminal: bool,
}

fn parse_args() -> Args {
    let mut chip = "STM32U585AIIx".to_string();
    let mut rtt_addr: Option<u64> = None;
    let mut terminal = false;
    let mut iter = std::env::args().skip(1);
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--chip" => chip = iter.next().expect("--chip needs a value"),
            "--rtt-addr" => {
                let s = iter.next().expect("--rtt-addr needs a hex value");
                let s = s.strip_prefix("0x").unwrap_or(&s);
                rtt_addr = Some(u64::from_str_radix(s, 16).expect("--rtt-addr must be hex"));
            }
            "--terminal" => terminal = true,
            "-h" | "--help" => {
                eprintln!(
                    "oled-mirror [--chip STM32U585AIIx] [--rtt-addr 0x30002e48] [--terminal]"
                );
                eprintln!("Flash first with: probe-rs download --chip <chip> <elf>");
                eprintln!("Get --rtt-addr with: arm-none-eabi-nm <elf> | grep _SEGGER_RTT");
                eprintln!("Default renders a scaled window; --terminal draws Braille on stdout.");
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(2);
            }
        }
    }
    Args {
        chip,
        rtt_addr,
        terminal,
    }
}

#[inline]
fn pixel(fb: &[u8; FB_BYTES], x: usize, y: usize) -> bool {
    let byte = fb[(y / 8) * SCREEN_W + x];
    (byte >> (y % 8)) & 1 != 0
}

/// Fill a native-resolution 128×32 ARGB buffer from the SSD1306 fb.
fn blit_native(fb: &[u8; FB_BYTES], out: &mut [u32; SCREEN_W * SCREEN_H]) {
    for y in 0..SCREEN_H {
        for x in 0..SCREEN_W {
            out[y * SCREEN_W + x] = if pixel(fb, x, y) { COLOR_ON } else { COLOR_OFF };
        }
    }
}

/// Nearest-neighbour scale the 128×32 buffer to a `(width × height)` surface.
fn present_scaled(
    src: &[u32; SCREEN_W * SCREEN_H],
    dst: &mut [u32],
    width: usize,
    height: usize,
) {
    for y in 0..height {
        let sy = y * SCREEN_H / height;
        let row_src = sy * SCREEN_W;
        let row_dst = y * width;
        for x in 0..width {
            let sx = x * SCREEN_W / width;
            dst[row_dst + x] = src[row_src + sx];
        }
    }
}

/// Render the 128×32 framebuffer as Braille (2×4 pixels per cell) with
/// ANSI cursor-home so successive frames overwrite in place without
/// flicker. Used only for the `--terminal` backend.
fn render_braille(fb: &[u8; FB_BYTES]) -> String {
    const COL0: [u8; 4] = [0, 1, 2, 6];
    const COL1: [u8; 4] = [3, 4, 5, 7];
    let mut out = String::with_capacity((SCREEN_W / 2 + 1) * (SCREEN_H / 4) + 16);
    out.push_str("\x1b[H");
    for cy in 0..SCREEN_H / 4 {
        for cx in 0..SCREEN_W / 2 {
            let mut bits: u32 = 0;
            for (dy, b) in COL0.iter().enumerate() {
                if pixel(fb, cx * 2, cy * 4 + dy) {
                    bits |= 1 << b;
                }
            }
            for (dy, b) in COL1.iter().enumerate() {
                if pixel(fb, cx * 2 + 1, cy * 4 + dy) {
                    bits |= 1 << b;
                }
            }
            out.push(char::from_u32(0x2800 + bits).unwrap_or(' '));
        }
        out.push('\n');
    }
    out
}

fn open_session(chip: &str) -> Result<Session> {
    let lister = Lister::new();
    let probes = lister.list_all();
    if probes.is_empty() {
        return Err(anyhow!("no debug probes found (is the ST-LINK plugged in?)"));
    }
    let probe = probes[0]
        .open()
        .with_context(|| format!("opening probe {}", probes[0].identifier))?;
    probe
        .attach(chip, Permissions::default())
        .with_context(|| format!("attaching to {chip}"))
}

/// Attach to the RTT control block after reset. Retries because the
/// firmware may still be in early init / splash animation when we first
/// look. Falls back to range scan if no `--rtt-addr` was supplied.
fn attach_rtt(session: &mut Session, rtt_addr: Option<u64>) -> Result<Rtt> {
    let memory_map = session.target().memory_map.clone();
    let scan = match rtt_addr {
        Some(a) => ScanRegion::Exact(a),
        None => ScanRegion::Range(0x3000_0000..0x3003_0000),
    };
    let sym_addr = rtt_addr.unwrap_or(0x3000_2e48);
    let mut last_err = None;
    for attempt in 0..32 {
        let mut core = session.core(0)?;
        match Rtt::attach_region(&mut core, &memory_map, &scan) {
            Ok(r) => return Ok(r),
            Err(e) => {
                if attempt == 0 || attempt == 8 || attempt == 20 {
                    let mut peek = [0u8; 16];
                    let mem = core
                        .read_8(sym_addr, &mut peek)
                        .map(|_| format!("{peek:02x?}"))
                        .unwrap_or_else(|re| format!("read err: {re}"));
                    let pc = match core.halt(Duration::from_millis(200)) {
                        Ok(_) => {
                            let p = core
                                .read_core_reg::<u32>(RegisterId(15))
                                .map(|v| format!("0x{v:08x}"))
                                .unwrap_or_else(|re| format!("read err: {re}"));
                            let _ = core.run();
                            p
                        }
                        Err(he) => format!("halt err: {he}"),
                    };
                    eprintln!("[oled-mirror] attempt {attempt}: PC={pc} _SEGGER_RTT={mem}");
                }
                last_err = Some(e);
            }
        }
        drop(core);
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(anyhow!(
        "attaching to RTT (firmware needs `ui-mirror` feature): {:?}",
        last_err
    ))
}

/// Read one byte-batch from the RTT channel into `acc`, then drain any
/// complete 516-byte frames into `pixels`. Returns whether at least one
/// new frame was decoded.
fn pump(
    core: &mut probe_rs::Core<'_>,
    channel: &probe_rs::rtt::UpChannel,
    buf: &mut [u8],
    acc: &mut Vec<u8>,
    pixels: &mut [u32; SCREEN_W * SCREEN_H],
    terminal: bool,
) -> Result<bool> {
    let n = channel.read(core, buf)?;
    if n == 0 {
        return Ok(false);
    }
    acc.extend_from_slice(&buf[..n]);
    let mut got = false;
    while acc.len() >= 4 + FB_BYTES {
        if acc[0] != HEADER[0] || acc[1] != HEADER[1] {
            acc.remove(0);
            continue;
        }
        let len = u16::from_le_bytes([acc[2], acc[3]]) as usize;
        if len != FB_BYTES {
            acc.remove(0);
            continue;
        }
        let fb: &[u8; FB_BYTES] = (&acc[4..4 + FB_BYTES]).try_into().unwrap();
        if terminal {
            print!("{}", render_braille(fb));
            let _ = std::io::stdout().flush();
        } else {
            blit_native(fb, pixels);
            got = true;
        }
        acc.drain(..4 + FB_BYTES);
    }
    Ok(got)
}

fn run_terminal(mut session: Session, rtt_addr: Option<u64>) -> Result<()> {
    let mut rtt = attach_rtt(&mut session, rtt_addr)?;
    let chans: Vec<(usize, Option<String>)> = rtt
        .up_channels()
        .iter()
        .map(|c| (c.number(), c.name().map(|s| s.to_string())))
        .collect();
    eprintln!("[oled-mirror] up channels: {chans:?}");
    let oled_num = chans
        .iter()
        .find(|(_, n)| n.as_deref() == Some("oled-fb"))
        .map(|(n, _)| *n)
        .or_else(|| chans.first().map(|(n, _)| *n))
        .ok_or_else(|| anyhow!("no up-channels — is `ui-mirror` enabled?"))?;
    let channel = rtt
        .up_channels()
        .take(oled_num)
        .expect("channel existed a line above");

    eprintln!("[oled-mirror] attached. Streaming 128x32 OLED (terminal). Ctrl-C to quit.");
    print!("\x1b[2J");
    std::io::stdout().flush()?;

    let mut core = session.core(0)?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut acc: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut pixels = [COLOR_OFF; SCREEN_W * SCREEN_H];
    let mut last_frame = Instant::now();
    loop {
        let got = pump(&mut core, &channel, &mut buf, &mut acc, &mut pixels, true)?;
        if got {
            last_frame = Instant::now();
        }
        let idle = last_frame.elapsed() > Duration::from_secs(1);
        std::thread::sleep(if idle {
            Duration::from_millis(50)
        } else {
            Duration::from_millis(16)
        });
    }
}

fn run_window(mut session: Session, rtt_addr: Option<u64>) -> Result<()> {
    let mut rtt = attach_rtt(&mut session, rtt_addr)?;
    let up_chans: Vec<(usize, Option<String>)> = rtt
        .up_channels()
        .iter()
        .map(|c| (c.number(), c.name().map(|s| s.to_string())))
        .collect();
    let down_chans: Vec<(usize, Option<String>)> = rtt
        .down_channels()
        .iter()
        .map(|c| (c.number(), c.name().map(|s| s.to_string())))
        .collect();
    eprintln!("[oled-mirror] up channels:   {up_chans:?}");
    eprintln!("[oled-mirror] down channels: {down_chans:?}");
    let oled_num = up_chans
        .iter()
        .find(|(_, n)| n.as_deref() == Some("oled-fb"))
        .map(|(n, _)| *n)
        .or_else(|| up_chans.first().map(|(n, _)| *n))
        .ok_or_else(|| anyhow!("no up-channels — is `ui-mirror` enabled?"))?;
    let channel = rtt
        .up_channels()
        .take(oled_num)
        .expect("channel existed a line above");
    // Optional: firmware with the down-channel (btn-in) receives key
    // events. rtt-target's channel names aren't always readable by
    // probe-rs, so fall back to channel 0 the same way we do up-side.
    let btn_num = down_chans
        .iter()
        .find(|(_, n)| n.as_deref() == Some("btn-in"))
        .map(|(n, _)| *n)
        .or_else(|| down_chans.first().map(|(n, _)| *n));
    let btn_channel = btn_num.and_then(|n| rtt.down_channels().take(n));
    if btn_channel.is_none() {
        eprintln!("[oled-mirror] no down-channel — window is read-only");
    }

    let event_loop = EventLoop::new().context("creating winit event loop")?;
    // Window title doubles as an always-visible keybinding cheat-sheet.
    // Kept short so it doesn't get truncated on narrow title bars.
    let title = if btn_channel.is_some() {
        "PQSigner OLED  -  short (</h/a | >/l/d)  long (Shift+</H/A | Shift+>/L/D)  Esc quit"
    } else {
        "PQSigner OLED  -  read-only (no btn-in)  |  Esc quit"
    };
    // softbuffer wants an owner it can Clone via Rc — winit gives us an
    // owned Window, so wrap it.
    let window = Rc::new(
        WindowBuilder::new()
            .with_title(title)
            .with_inner_size(LogicalSize::new(
                (SCREEN_W * 8) as u32,
                (SCREEN_H * 8) as u32,
            ))
            .with_min_inner_size(LogicalSize::new(SCREEN_W as u32, SCREEN_H as u32))
            .with_resizable(true)
            .build(&event_loop)
            .context("building window")?,
    );
    let context = softbuffer::Context::new(window.clone())
        .map_err(|e| anyhow!("softbuffer::Context: {e}"))?;
    let mut surface = softbuffer::Surface::new(&context, window.clone())
        .map_err(|e| anyhow!("softbuffer::Surface: {e}"))?;

    eprintln!("[oled-mirror] attached. Streaming 128x32 OLED (window).");
    if btn_channel.is_some() {
        eprintln!("[oled-mirror] keys:");
        eprintln!("    <  / h / a          LEFT  button  (short press)");
        eprintln!("    >  / l / d          RIGHT button  (short press)");
        eprintln!("    Shift+<  / H / A    LEFT  button  (long press)");
        eprintln!("    Shift+>  / L / D    RIGHT button  (long press)");
        eprintln!("    Esc                 quit");
        eprintln!("    (click the window first so it has keyboard focus)");
    } else {
        eprintln!("[oled-mirror] read-only mode - no button channel. Esc quits.");
    }

    let mut core = session.core(0)?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut acc: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut pixels = [COLOR_OFF; SCREEN_W * SCREEN_H];
    let mut dirty = true; // first redraw paints the initial clear color
    let mut btn_channel = btn_channel;
    // Shift state for mapping Shift+ArrowLeft/Right → long-press bytes.
    // winit's logical_key already applies shift for letter keys, but
    // named keys (arrows) do not, so we track it ourselves.
    let mut shift = false;

    event_loop
        .run(move |event, elwt| {
            elwt.set_control_flow(ControlFlow::Poll);
            match event {
                Event::WindowEvent { event, .. } => match event {
                    WindowEvent::CloseRequested => elwt.exit(),
                    WindowEvent::ModifiersChanged(m) => {
                        shift = m.state().shift_key();
                    }
                    WindowEvent::KeyboardInput {
                        event:
                            KeyEvent {
                                logical_key,
                                state: ElementState::Pressed,
                                repeat: false,
                                ..
                            },
                        ..
                    } => {
                        // Quick exit.
                        if matches!(&logical_key, Key::Named(NamedKey::Escape)) {
                            elwt.exit();
                            return;
                        }
                        // Map to the same byte protocol the firmware's
                        // semihosting path already understands:
                        //   h/a=LEFT short, l/d=RIGHT short, H/A=LEFT
                        //   long, L/D=RIGHT long.
                        let byte: Option<u8> = match &logical_key {
                            Key::Named(NamedKey::ArrowLeft) => {
                                Some(if shift { b'H' } else { b'h' })
                            }
                            Key::Named(NamedKey::ArrowRight) => {
                                Some(if shift { b'L' } else { b'l' })
                            }
                            Key::Character(s) => match s.as_str() {
                                "h" | "a" => Some(b'h'),
                                "l" | "d" => Some(b'l'),
                                "H" | "A" => Some(b'H'),
                                "L" | "D" => Some(b'L'),
                                _ => None,
                            },
                            _ => None,
                        };
                        if let (Some(b), Some(ch)) = (byte, btn_channel.as_mut()) {
                            if let Err(e) = ch.write(&mut core, &[b]) {
                                eprintln!("[oled-mirror] btn-in write: {e}");
                            }
                        }
                    }
                    WindowEvent::Resized(_) => {
                        window.request_redraw();
                    }
                    WindowEvent::RedrawRequested => {
                        let size = window.inner_size();
                        let (Some(w), Some(h)) =
                            (NonZeroU32::new(size.width), NonZeroU32::new(size.height))
                        else {
                            return;
                        };
                        if let Err(e) = surface.resize(w, h) {
                            eprintln!("[oled-mirror] surface.resize: {e}");
                            return;
                        }
                        let mut dst = match surface.buffer_mut() {
                            Ok(b) => b,
                            Err(e) => {
                                eprintln!("[oled-mirror] surface.buffer_mut: {e}");
                                return;
                            }
                        };
                        present_scaled(&pixels, &mut dst, w.get() as usize, h.get() as usize);
                        if let Err(e) = dst.present() {
                            eprintln!("[oled-mirror] buffer.present: {e}");
                        }
                    }
                    _ => {}
                },
                // AboutToWait fires each iteration of the event loop when
                // ControlFlow::Poll is set — the right hook to poll RTT.
                Event::AboutToWait => {
                    match pump(&mut core, &channel, &mut buf, &mut acc, &mut pixels, false) {
                        Ok(true) => {
                            dirty = true;
                            window.request_redraw();
                        }
                        Ok(false) => {}
                        Err(e) => {
                            eprintln!("[oled-mirror] RTT read error: {e}");
                            elwt.exit();
                            return;
                        }
                    }
                    if dirty {
                        dirty = false;
                        window.request_redraw();
                    }
                    // ~60 Hz; keeps CPU use low without starving RTT.
                    std::thread::sleep(Duration::from_millis(16));
                }
                _ => {}
            }
        })
        .map_err(|e| anyhow!("event loop: {e}"))?;
    Ok(())
}

fn main() -> Result<()> {
    let args = parse_args();
    let mut session = open_session(&args.chip)?;

    // Reset and run so the firmware starts from main(), then give it a
    // moment to call `ui::init()` and create the RTT control block before
    // we scan for it.
    {
        let mut core = session.core(0)?;
        core.reset_and_halt(Duration::from_secs(1))?;
        core.run()?;
    }

    if args.terminal {
        run_terminal(session, args.rtt_addr)
    } else {
        run_window(session, args.rtt_addr)
    }
}
