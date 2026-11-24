//! The hysteresis of the readiness of a pod (FR-85): two consecutive local verdicts withdraw it,
//! three consecutive fresh verdicts give it back.

/// How many consecutive verdicts that call for shedding withdraw the readiness.
pub const SHED_AFTER: u8 = 2;

/// How many consecutive fresh verdicts restore the readiness.
pub const RESTORE_AFTER: u8 = 3;

/// What one check asks of the readiness of the pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessPressure {
    /// The pod is fresh.
    Settled,
    /// The pod is stale and may leave the load balancer: a local or zone-shaped problem that no
    /// zone floor protects.
    Shed,
    /// The pod is stale and must stay in the load balancer: a fleet-wide problem, or the zone
    /// floor protects it. It fails closed per request instead.
    Hold,
}

/// A change of the readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessTransition {
    /// The readiness stays as it was.
    Unchanged,
    /// The pod failed readiness and sheds its connections.
    BecameUnready,
    /// The pod is ready again.
    BecameReady,
}

/// The readiness of the pod with its streak counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadinessHysteresis {
    ready: bool,
    streak: u8,
}

impl Default for ReadinessHysteresis {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadinessHysteresis {
    /// A pod that is ready.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ready: true,
            streak: 0,
        }
    }

    /// Whether the pod is ready.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        self.ready
    }

    /// Takes one verdict into account.
    pub const fn step(&mut self, pressure: ReadinessPressure) -> ReadinessTransition {
        if self.ready {
            self.step_ready(pressure)
        } else {
            self.step_unready(pressure)
        }
    }

    const fn step_ready(&mut self, pressure: ReadinessPressure) -> ReadinessTransition {
        match pressure {
            ReadinessPressure::Shed => {
                self.streak = self.streak.saturating_add(1);
                if self.streak >= SHED_AFTER {
                    self.ready = false;
                    self.streak = 0;
                    return ReadinessTransition::BecameUnready;
                }
            }
            ReadinessPressure::Settled | ReadinessPressure::Hold => self.streak = 0,
        }
        ReadinessTransition::Unchanged
    }

    const fn step_unready(&mut self, pressure: ReadinessPressure) -> ReadinessTransition {
        match pressure {
            ReadinessPressure::Settled => {
                self.streak = self.streak.saturating_add(1);
                if self.streak >= RESTORE_AFTER {
                    return self.restore();
                }
            }
            ReadinessPressure::Hold => return self.restore(),
            ReadinessPressure::Shed => self.streak = 0,
        }
        ReadinessTransition::Unchanged
    }

    const fn restore(&mut self) -> ReadinessTransition {
        self.ready = true;
        self.streak = 0;
        ReadinessTransition::BecameReady
    }
}

#[cfg(test)]
mod tests;
