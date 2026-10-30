// SPDX-License-Identifier: GPL-3.0-only

use crate::event::Event;
use crate::error::Result;

/// Streaming consumer for events.
pub trait EventSink {
    fn push(&mut self, event: Event) -> Result<()>;
    fn push_batch(&mut self, batch: Vec<Event>) -> Result<()> {
        for e in batch {
            self.push(e)?;
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Collects events into a Vec (tests / small runs).
#[derive(Debug, Default)]
pub struct VecSink {
    pub events: Vec<Event>,
}

impl EventSink for VecSink {
    fn push(&mut self, event: Event) -> Result<()> {
        self.events.push(event);
        Ok(())
    }
}
