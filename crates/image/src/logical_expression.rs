use std::collections::BTreeSet;

use crate::model::{CountTest, Expression};

pub const MOST_SUBSIGNATURES: usize = 64;
pub const DEEPEST_EXPRESSION: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpressionStep {
    Subsignature {
        index: u16,
        count: Option<CountTest>,
    },
    All,
    Any,
    Block(CountTest),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpressionNotCompiled {
    TooDeep,
    SubsignatureOutOfRange { index: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpressionMalformed;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Evaluated {
    satisfied: bool,
    matches: u64,
    matched_subsignatures: u64,
}

const UNSATISFIED: Evaluated = Evaluated {
    satisfied: false,
    matches: 0,
    matched_subsignatures: 0,
};

pub fn postfix_steps(
    expression: &Expression,
    subsignature_count: usize,
) -> Result<Vec<ExpressionStep>, ExpressionNotCompiled> {
    let mut steps = Vec::new();
    append_steps(expression, subsignature_count, 1, &mut steps)?;
    Ok(steps)
}

fn append_steps(
    expression: &Expression,
    subsignature_count: usize,
    depth: usize,
    steps: &mut Vec<ExpressionStep>,
) -> Result<(), ExpressionNotCompiled> {
    if depth > DEEPEST_EXPRESSION {
        return Err(ExpressionNotCompiled::TooDeep);
    }
    let deeper = depth.saturating_add(1);
    match expression {
        Expression::Subsignature { index, count } => {
            if usize::from(*index) >= subsignature_count.min(MOST_SUBSIGNATURES) {
                return Err(ExpressionNotCompiled::SubsignatureOutOfRange { index: *index });
            }
            steps.push(ExpressionStep::Subsignature {
                index: *index,
                count: *count,
            });
        }
        Expression::All(left, right) | Expression::Any(left, right) => {
            append_steps(left, subsignature_count, deeper, steps)?;
            append_steps(right, subsignature_count, deeper, steps)?;
            steps.push(if matches!(expression, Expression::All(..)) {
                ExpressionStep::All
            } else {
                ExpressionStep::Any
            });
        }
        Expression::Block { inner, count } => {
            append_steps(inner, subsignature_count, deeper, steps)?;
            steps.push(ExpressionStep::Block(*count));
        }
    }
    Ok(())
}

pub fn expression_holds(
    steps: impl IntoIterator<Item = Result<ExpressionStep, ExpressionMalformed>>,
    matches_of: impl Fn(u16) -> u64,
) -> Result<bool, ExpressionMalformed> {
    let mut stack: Vec<Evaluated> = Vec::new();
    for step in steps {
        let evaluated = match step? {
            ExpressionStep::Subsignature { index, count } => {
                let matches = matches_of(index);
                let satisfied = match count {
                    None => matches > 0,
                    Some(test) => test.comparison.holds_for(matches) && test.distinct_at_least <= 1,
                };
                if satisfied {
                    Evaluated {
                        satisfied,
                        matches,
                        matched_subsignatures: 1u64.checked_shl(u32::from(index)).unwrap_or(0),
                    }
                } else {
                    UNSATISFIED
                }
            }
            ExpressionStep::All => {
                let right = stack.pop().ok_or(ExpressionMalformed)?;
                let left = stack.pop().ok_or(ExpressionMalformed)?;
                combined(left, right, true)
            }
            ExpressionStep::Any => {
                let right = stack.pop().ok_or(ExpressionMalformed)?;
                let left = stack.pop().ok_or(ExpressionMalformed)?;
                combined(left, right, false)
            }
            ExpressionStep::Block(test) => {
                let inner = stack.pop().ok_or(ExpressionMalformed)?;
                let inner = if inner.satisfied { inner } else { UNSATISFIED };
                let distinct = inner.matched_subsignatures.count_ones();
                if test.comparison.holds_for(inner.matches) && distinct >= test.distinct_at_least {
                    Evaluated {
                        satisfied: true,
                        matches: inner.matches,
                        matched_subsignatures: 0,
                    }
                } else {
                    UNSATISFIED
                }
            }
        };
        stack.push(evaluated);
    }
    match stack.as_slice() {
        [only] => Ok(only.satisfied),
        _ => Err(ExpressionMalformed),
    }
}

fn combined(left: Evaluated, right: Evaluated, all: bool) -> Evaluated {
    let satisfied = if all {
        left.satisfied && right.satisfied
    } else {
        left.satisfied || right.satisfied
    };
    if !satisfied {
        return UNSATISFIED;
    }
    let mut matches: u64 = 0;
    let mut matched_subsignatures = 0;
    for side in [left, right] {
        if side.satisfied {
            matches = matches.saturating_add(side.matches);
            matched_subsignatures |= side.matched_subsignatures;
        }
    }
    Evaluated {
        satisfied,
        matches,
        matched_subsignatures,
    }
}

#[must_use]
pub fn holds_with_no_matches(steps: &[ExpressionStep]) -> bool {
    expression_holds(steps.iter().copied().map(Ok), |_| 0).unwrap_or(false)
}

#[must_use]
pub fn count_ceilings(expression: &Expression, subsignature_count: usize) -> Vec<u32> {
    let mut ceilings = vec![1u32; subsignature_count];
    raise_ceilings(expression, 0, &mut ceilings);
    ceilings
}

fn raise_ceilings(expression: &Expression, enclosing: u32, ceilings: &mut [u32]) {
    match expression {
        Expression::Subsignature { index, count } => {
            let own = count.map_or(0, |test| test.comparison.threshold());
            if let Some(ceiling) = ceilings.get_mut(usize::from(*index)) {
                *ceiling = (*ceiling).max(enclosing.max(own).saturating_add(1));
            }
        }
        Expression::All(left, right) | Expression::Any(left, right) => {
            raise_ceilings(left, enclosing, ceilings);
            raise_ceilings(right, enclosing, ceilings);
        }
        Expression::Block { inner, count } => {
            raise_ceilings(inner, enclosing.max(count.comparison.threshold()), ceilings);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Gate {
    cost: u64,
    subsignatures: BTreeSet<u16>,
}

#[must_use]
pub fn gate_of(expression: &Expression, cost_of: &dyn Fn(u16) -> u64) -> Option<BTreeSet<u16>> {
    gate(expression, cost_of).map(|gate| gate.subsignatures)
}

fn gate(expression: &Expression, cost_of: &dyn Fn(u16) -> u64) -> Option<Gate> {
    match expression {
        Expression::Subsignature { index, count } => {
            let holds_without_matches = count
                .is_some_and(|test| test.comparison.holds_for(0) && test.distinct_at_least <= 1);
            (!holds_without_matches).then(|| Gate {
                cost: cost_of(*index),
                subsignatures: BTreeSet::from([*index]),
            })
        }
        Expression::All(left, right) => cheaper(gate(left, cost_of), gate(right, cost_of)),
        Expression::Any(left, right) => {
            let left = gate(left, cost_of)?;
            let right = gate(right, cost_of)?;
            let mut subsignatures = left.subsignatures;
            subsignatures.extend(right.subsignatures);
            Some(Gate {
                cost: subsignatures
                    .iter()
                    .fold(0u64, |cost, index| cost.saturating_add(cost_of(*index))),
                subsignatures,
            })
        }
        Expression::Block { inner, count } => {
            let holds_without_any = count.comparison.holds_for(0);
            if holds_without_any && count.distinct_at_least == 0 {
                return None;
            }
            let inner_gate = gate(inner, cost_of);
            if holds_without_any {
                return inner_gate;
            }
            let mut leaves = BTreeSet::new();
            collect_leaves(inner, &mut leaves);
            let every_leaf = Gate {
                cost: leaves
                    .iter()
                    .fold(0u64, |cost, index| cost.saturating_add(cost_of(*index))),
                subsignatures: leaves,
            };
            cheaper(inner_gate, Some(every_leaf))
        }
    }
}

fn cheaper(left: Option<Gate>, right: Option<Gate>) -> Option<Gate> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if right.cost < left.cost { right } else { left }),
        (left, right) => left.or(right),
    }
}

fn collect_leaves(expression: &Expression, leaves: &mut BTreeSet<u16>) {
    match expression {
        Expression::Subsignature { index, .. } => {
            leaves.insert(*index);
        }
        Expression::All(left, right) | Expression::Any(left, right) => {
            collect_leaves(left, leaves);
            collect_leaves(right, leaves);
        }
        Expression::Block { inner, .. } => collect_leaves(inner, leaves),
    }
}
