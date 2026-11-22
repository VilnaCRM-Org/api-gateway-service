//! Event subscribers of the IAM context.
//!
//! This module is empty on purpose: durable reactions to IAM events go through the outbox, which a
//! relay publishes, and not through the in-process event bus, so no subscriber is registered here.
