//! Integration tests of the service binary: it is spawned as a process, with a cleared environment.

#[cfg(test)]
mod authentication;
#[cfg(test)]
mod bootstrap;
#[cfg(test)]
mod check_config;
#[cfg(test)]
mod export;
#[cfg(test)]
mod gateway;
#[cfg(test)]
mod healthcheck;
#[cfg(test)]
mod iam_bootstrap;
#[cfg(test)]
mod maintenance;
#[cfg(test)]
mod migrate;
#[cfg(test)]
mod outbox_listener;
#[cfg(test)]
mod panic;
#[cfg(test)]
mod publish_wait;
#[cfg(test)]
mod register_iam_specs;
#[cfg(test)]
mod rejected_attempts;
#[cfg(test)]
mod serve;
#[cfg(test)]
mod singleton_tasks;
#[cfg(test)]
mod support;
#[cfg(test)]
mod template_seams;
