//! The limits of a document, checked on the parsed tree before any field is resolved.

use std::collections::{HashMap, HashSet};

use async_graphql::Name;
use async_graphql::parser::Positioned;
use async_graphql::parser::types::{
    ExecutableDocument, FragmentDefinition, OperationDefinition, Selection, SelectionSet,
};
use iam_domain::{DocumentLimits, DocumentRefusal, LimitKind};

/// The deepest structural nesting the recursive walks accept: selection sets, inline fragments
/// and fragment spreads together, fragments expanded.
///
/// Inline fragments and spreads add no field depth, so the field depth limit alone does not bound
/// the stack: a hundred fragments that each nest inline fragments to the text limit would recurse
/// thousands of levels deep. This cap is checked before resolution, so the resolver's recursion is
/// bounded by it too.
const MAX_STRUCTURE: usize = 128;

/// Refuses a document with too many fragments, aliases or field selections.
///
/// The counts cover every operation and fragment of the text, each fragment once however often it
/// is spread, so the walk is linear in the size of the text.
pub(super) fn check_counts(
    document: &ExecutableDocument,
    limits: &DocumentLimits,
) -> Result<(), DocumentRefusal> {
    if document.fragments.len() > limits.fragments {
        return Err(DocumentRefusal::LimitsExceeded(LimitKind::Fragments));
    }
    let operations = document
        .operations
        .iter()
        .map(|(_, operation)| &operation.node.selection_set.node);
    let fragments = document
        .fragments
        .values()
        .map(|fragment| &fragment.node.selection_set.node);
    let counts = operations.chain(fragments).fold(Counts::default(), count);
    if counts.aliases > limits.aliases {
        return Err(DocumentRefusal::LimitsExceeded(LimitKind::Aliases));
    }
    if counts.fields > limits.coordinates {
        return Err(DocumentRefusal::LimitsExceeded(LimitKind::Coordinates));
    }
    Ok(())
}

/// Refuses an operation whose selection sets nest deeper than the limit once its fragments are
/// expanded, a fragment that is undefined and a cycle of fragments.
pub(super) fn check_depth(
    document: &ExecutableDocument,
    operation: &OperationDefinition,
    limits: &DocumentLimits,
) -> Result<(), DocumentRefusal> {
    let mut walker = DepthWalker {
        fragments: &document.fragments,
        memo: HashMap::new(),
        active: HashSet::new(),
    };
    let depth = walker.set_depth(&operation.selection_set.node, 0)?;
    if depth.fields > limits.depth {
        return Err(DocumentRefusal::LimitsExceeded(LimitKind::Depth));
    }
    Ok(())
}

#[derive(Default)]
struct Counts {
    fields: usize,
    aliases: usize,
}

/// Adds the fields and aliases of the selection set and of everything nested in it.
fn count(mut counts: Counts, set: &SelectionSet) -> Counts {
    let mut pending = vec![set];
    while let Some(current) = pending.pop() {
        for item in &current.items {
            match &item.node {
                Selection::Field(field) => {
                    counts.fields = counts.fields.saturating_add(1);
                    counts.aliases = counts
                        .aliases
                        .saturating_add(usize::from(field.node.alias.is_some()));
                    pending.push(&field.node.selection_set.node);
                }
                Selection::InlineFragment(fragment) => {
                    pending.push(&fragment.node.selection_set.node);
                }
                Selection::FragmentSpread(_) => {}
            }
        }
    }
    counts
}

/// The nesting below a selection set: the field levels, which the depth limit counts, and the
/// structural levels, which bound the recursion.
#[derive(Debug, Clone, Copy, Default)]
struct Depth {
    fields: usize,
    structure: usize,
}

impl Depth {
    /// This depth one structural level further down, `fields` field levels deeper.
    const fn nested(self, fields: usize) -> Self {
        Self {
            fields: self.fields.saturating_add(fields),
            structure: self.structure.saturating_add(1),
        }
    }

    fn max(self, other: Self) -> Self {
        Self {
            fields: self.fields.max(other.fields),
            structure: self.structure.max(other.structure),
        }
    }
}

/// Refuses a structural level past [`MAX_STRUCTURE`].
const fn within_structure(level: usize) -> Result<(), DocumentRefusal> {
    if level > MAX_STRUCTURE {
        Err(DocumentRefusal::LimitsExceeded(LimitKind::Depth))
    } else {
        Ok(())
    }
}

struct DepthWalker<'a> {
    fragments: &'a HashMap<Name, Positioned<FragmentDefinition>>,
    memo: HashMap<&'a str, Depth>,
    active: HashSet<&'a str>,
}

impl<'a> DepthWalker<'a> {
    /// The deepest nesting below a selection set at structural `level`: a field adds one field
    /// level, and every selection adds one structural level.
    fn set_depth(&mut self, set: &'a SelectionSet, level: usize) -> Result<Depth, DocumentRefusal> {
        within_structure(level)?;
        let below = level.saturating_add(1);
        let mut deepest = Depth::default();
        for item in &set.items {
            let depth = match &item.node {
                Selection::Field(field) => self
                    .set_depth(&field.node.selection_set.node, below)?
                    .nested(1),
                Selection::InlineFragment(fragment) => self
                    .set_depth(&fragment.node.selection_set.node, below)?
                    .nested(0),
                Selection::FragmentSpread(spread) => self
                    .fragment_depth(spread.node.fragment_name.node.as_str(), below)?
                    .nested(0),
            };
            deepest = deepest.max(depth);
        }
        Ok(deepest)
    }

    /// The depth of a fragment, computed once; every use still checks that its structure fits
    /// below `level`.
    fn fragment_depth(&mut self, name: &'a str, level: usize) -> Result<Depth, DocumentRefusal> {
        if let Some(depth) = self.memo.get(name) {
            within_structure(level.saturating_add(depth.structure))?;
            return Ok(*depth);
        }
        let fragment = self
            .fragments
            .get(name)
            .ok_or(DocumentRefusal::MalformedOperation)?;
        if !self.active.insert(name) {
            return Err(DocumentRefusal::MalformedOperation);
        }
        let depth = self.set_depth(&fragment.node.selection_set.node, level)?;
        self.active.remove(name);
        self.memo.insert(name, depth);
        Ok(depth)
    }
}
