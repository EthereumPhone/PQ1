//! Bookkeeping for streaming one frame's bands to the panel in the
//! background (#934 stage 2, the busy film only).
//!
//! The thread renders the bands in order and queues each one; the DMA
//! completion interrupt finishes a band and starts the next queued one. One
//! DMA channel carries the stream, so at most one band is on the wire, and
//! bands go out strictly in order (the panel auto-increments through one
//! window). The two sides share these counters under a critical section on
//! the thread's side; the rules live here so they are host-tested rather than
//! trusted on the device.
//!
//! Display only: nothing here decides what is signed.

/// What the caller does after an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Start sending band `n` (its index in the frame) now.
    Start(u8),
    /// Nothing to start: a band is on the wire, or the next one is not
    /// queued yet (the next event starts it).
    Idle,
    /// Every band has been sent: close the stream.
    Finished,
}

/// The counters of one frame's stream: `total` bands, of which `queued` are
/// rendered and handed over, `started` have been put on the wire and `sent`
/// have left it. Always `sent <= started <= queued <= total`, and
/// `started - sent <= 1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BandQueue {
    total: u8,
    queued: u8,
    started: u8,
    sent: u8,
}

impl BandQueue {
    /// A stream of `total` bands, none queued.
    #[must_use]
    pub const fn new(total: u8) -> Self {
        Self { total, queued: 0, started: 0, sent: 0 }
    }

    /// The thread has rendered the next band and hands it over. `None` if
    /// every band was already queued (a caller bug, refused); otherwise what
    /// to do: start it at once when the wire is idle, else nothing (the
    /// completion of the band on the wire starts it).
    pub fn queue(&mut self) -> Option<Step> {
        if self.queued >= self.total {
            return None;
        }
        self.queued += 1;
        Some(self.next())
    }

    /// The band on the wire has been sent (DMA complete and the SPI drained).
    /// `None` if no band was on the wire (a spurious completion, ignored).
    pub fn sent(&mut self) -> Option<Step> {
        if self.started == self.sent {
            return None;
        }
        self.sent += 1;
        if self.sent == self.total {
            return Some(Step::Finished);
        }
        Some(self.next())
    }

    fn next(&mut self) -> Step {
        if self.started == self.sent && self.started < self.queued {
            let n = self.started;
            self.started += 1;
            Step::Start(n)
        } else {
            Step::Idle
        }
    }

    /// Whether band `k` may be rendered into buffer `k % n_buf`: the band
    /// that last used that buffer, `k - n_buf`, has left the wire.
    #[must_use]
    pub fn buffer_free(&self, k: u8, n_buf: u8) -> bool {
        u16::from(k) < u16::from(self.sent) + u16::from(n_buf)
    }

    /// Bands queued so far.
    #[must_use]
    pub fn queued_count(&self) -> u8 {
        self.queued
    }

    /// Bands sent so far.
    #[must_use]
    pub fn sent_count(&self) -> u8 {
        self.sent
    }

    /// Whether every band has been sent.
    #[must_use]
    pub fn finished(&self) -> bool {
        self.total > 0 && self.sent == self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_before_completion_waits_for_the_wire() {
        let mut q = BandQueue::new(3);
        assert_eq!(q.queue(), Some(Step::Start(0)));
        assert_eq!(q.queue(), Some(Step::Idle), "band 0 is on the wire");
        assert_eq!(q.queue(), Some(Step::Idle));
        assert_eq!(q.sent(), Some(Step::Start(1)));
        assert_eq!(q.sent(), Some(Step::Start(2)));
        assert_eq!(q.sent(), Some(Step::Finished));
        assert!(q.finished());
    }

    #[test]
    fn completion_before_queue_lets_the_queue_start_it() {
        // The thread is still rendering band 1 when band 0 leaves the wire:
        // the completion finds nothing queued, and the queue starts it.
        let mut q = BandQueue::new(2);
        assert_eq!(q.queue(), Some(Step::Start(0)));
        assert_eq!(q.sent(), Some(Step::Idle));
        assert_eq!(q.queue(), Some(Step::Start(1)));
        assert_eq!(q.sent(), Some(Step::Finished));
    }

    #[test]
    fn refuses_overqueue_and_spurious_completions() {
        let mut q = BandQueue::new(1);
        assert_eq!(q.sent(), None, "nothing on the wire");
        assert_eq!(q.queue(), Some(Step::Start(0)));
        assert_eq!(q.queue(), None, "all bands already queued");
        assert_eq!(q.sent(), Some(Step::Finished));
        assert_eq!(q.sent(), None);
    }

    #[test]
    fn a_buffer_is_reused_only_after_its_band_left_the_wire() {
        let mut q = BandQueue::new(6);
        for k in 0..4 {
            assert!(q.buffer_free(k, 4));
        }
        assert!(!q.buffer_free(4, 4), "band 0 still holds buffer 0");
        let _ = q.queue();
        let _ = q.sent();
        assert!(q.buffer_free(4, 4));
        assert!(!q.buffer_free(5, 4));
    }

    /// Every interleaving of the two sides, for every frame size the film
    /// can stream: one band on the wire at most, bands started in order and
    /// only once queued, buffers never reused early, and `Finished` exactly
    /// once, after the last band.
    #[test]
    fn every_interleaving_keeps_the_invariants() {
        const N_BUF: u8 = 4;
        for total in 1..=9u8 {
            // Event strings over {q, s}: explore all of them breadth-first.
            let mut frontier = std::vec![(BandQueue::new(total), std::vec::Vec::<u8>::new(), 0u8, false)];
            while let Some((q, starts, rendered, done)) = frontier.pop() {
                assert!(q.sent <= q.started && q.started <= q.queued && q.queued <= q.total);
                assert!(q.started - q.sent <= 1, "one band on the wire");
                assert_eq!(starts.len(), q.started as usize);
                assert!(starts.iter().enumerate().all(|(i, &n)| n as usize == i), "in order");
                if done {
                    assert!(q.finished());
                    continue;
                }
                // The thread renders band `rendered` only when its buffer is
                // free, then queues it.
                if rendered < total && q.buffer_free(rendered, N_BUF) {
                    // The band that last used this buffer has left the wire.
                    assert!(rendered < N_BUF || rendered - N_BUF < q.sent);
                    let mut q2 = q;
                    let mut s2 = starts.clone();
                    match q2.queue().expect("not over-queued") {
                        Step::Start(n) => s2.push(n),
                        Step::Idle => {}
                        Step::Finished => panic!("queue never finishes"),
                    }
                    frontier.push((q2, s2, rendered + 1, false));
                }
                // The wire completes a band, if one is on it.
                if q.started > q.sent {
                    let mut q2 = q;
                    let mut s2 = starts.clone();
                    let fin = match q2.sent().expect("a band was on the wire") {
                        Step::Start(n) => {
                            s2.push(n);
                            false
                        }
                        Step::Idle => false,
                        Step::Finished => {
                            assert_eq!(q2.sent, total, "finished only after the last band");
                            true
                        }
                    };
                    frontier.push((q2, s2, rendered, fin));
                }
                // No deadlock: something can always happen until done.
                assert!(
                    (rendered < total && q.buffer_free(rendered, N_BUF)) || q.started > q.sent,
                    "stuck at {q:?}, rendered {rendered}"
                );
            }
        }
    }
}
