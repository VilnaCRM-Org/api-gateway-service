//! Catalogue change fixtures of the IAM context.

use iam_domain::{CatalogueStatement, ChangeStatement, DecisionEffect, IamChange};

use crate::seed::TestRng;
use crate::unit_of_work::{iam_change, rebuilt};

/// A random committed change with `effect` that runs the activation `statements`, written by a
/// random user.
pub fn catalogue_change(
    rng: &mut TestRng,
    effect: DecisionEffect,
    statements: Vec<CatalogueStatement>,
) -> IamChange {
    rebuilt(&iam_change(rng, effect, 0), |parts| {
        parts.statements = statements
            .into_iter()
            .map(|statement| ChangeStatement::ApplyCatalogue(Box::new(statement)))
            .collect();
    })
}

#[cfg(test)]
mod tests;
