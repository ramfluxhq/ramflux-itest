// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Plan only the remaining admissions in one inspected durable daily prefix window.
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const DAY: u64 = 86_400;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DailyBudgetPlan {
    pub(crate) prefix: Option<String>,
    pub(crate) observed_count: u64,
    pub(crate) start_count: u64,
    pub(crate) limit: u64,
    pub(crate) reset_at: u64,
}

impl DailyBudgetPlan {
    /// A fresh private fixture may supply its known configured limit when no row exists yet.
    /// An operator node must identify an existing row and cannot invent a zero start count.
    pub(crate) fn inspect(
        inspection: &Value,
        prefix: Option<&str>,
        fresh_fixture_limit: Option<u64>,
    ) -> TestResult<Self> {
        let now = number(inspection, "observed_at")?;
        let rows = inspection["rows"].as_array().ok_or("budget rows missing")?;
        let mut matches = rows.iter().filter(|row| {
            row["scope"] == "prefix"
                && row["budget"] == "publication_daily"
                && prefix.is_none_or(|prefix| row["prefix"].as_str() == Some(prefix))
        });
        let row = matches.next();
        if matches.next().is_some() {
            return Err("ambiguous daily prefix rows; select the client's prefix hash".into());
        }
        let plan = if let Some(row) = row {
            let reset = number(row, "reset_at")?;
            if reset % DAY != 0 {
                return Err("durable daily reset is not a UTC day boundary".into());
            }
            let observed_count = number(row, "count")?;
            Self {
                prefix: Some(row["prefix"].as_str().ok_or("prefix hash missing")?.to_owned()),
                observed_count,
                start_count: if reset > now { observed_count } else { 0 },
                limit: number(row, "limit")?,
                reset_at: if reset > now { reset } else { next_reset(now)? },
            }
        } else if rows.is_empty() && prefix.is_none() {
            Self {
                prefix: None,
                observed_count: 0,
                start_count: 0,
                limit: fresh_fixture_limit.ok_or("operator prefix receipt missing")?,
                reset_at: next_reset(now)?,
            }
        } else {
            return Err("selected daily prefix receipt missing".into());
        };
        if plan.limit == 0 {
            return Err("daily prefix limit is zero".into());
        }
        // Refuse before creating anything if another scope would exhaust first.
        for row in rows {
            if row["scope"] == "global" && row["budget"] == "publication_daily" {
                let count = if number(row, "reset_at")? > now { number(row, "count")? } else { 0 };
                if plan.remaining() > 0
                    && number(row, "limit")?.saturating_sub(count) <= plan.remaining()
                {
                    return Err("global daily headroom must exceed the prefix remainder".into());
                }
            }
        }
        Ok(plan)
    }

    #[must_use]
    pub(crate) fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.start_count)
    }

    pub(crate) fn verify_progress(&self, inspection: &Value, accepted: u64) -> TestResult<()> {
        if number(inspection, "observed_at")? >= self.reset_at {
            return Err("the inspected daily window ended during the slice".into());
        }
        let fresh = (accepted == 0 && self.prefix.is_none()).then_some(self.limit);
        let current = Self::inspect(inspection, self.prefix.as_deref(), fresh)?;
        let expected = self.start_count.checked_add(accepted).ok_or("admission count overflow")?;
        if current.limit != self.limit
            || current.reset_at != self.reset_at
            || current.start_count != expected
        {
            return Err(format!("durable quota drift: expected count={expected}, limit={}, reset={}; observed {current:?}", self.limit, self.reset_at).into());
        }
        Ok(())
    }
}

fn next_reset(now: u64) -> TestResult<u64> {
    (now / DAY)
        .checked_add(1)
        .and_then(|day| day.checked_mul(DAY))
        .ok_or_else(|| "daily reset overflow".into())
}

fn number(row: &Value, name: &str) -> TestResult<u64> {
    row[name].as_u64().ok_or_else(|| format!("missing unsigned quota field {name}").into())
}

pub(crate) fn require_daily_capacity_hint(status: &Value, reset: u64) -> TestResult {
    let capacity = &status["networking_reason"]["capacity"];
    if capacity["scope"] != "prefix_daily" {
        return Err(format!("expected prefix_daily capacity hint: {status}").into());
    }
    if capacity["resets_at_unix"].as_u64().ok_or("capacity reset missing")? != reset {
        return Err(format!("capacity hint differs from durable reset {reset}: {status}").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inspection(count: u64) -> Value {
        json!({"observed_at":100_000,"rows":[
            {"scope":"global","budget":"publication_daily","count":20,"limit":256,"reset_at":172_800},
            {"scope":"prefix","prefix":"fixture-prefix","budget":"publication_daily","count":count,"limit":8,"reset_at":172_800}
        ]})
    }

    // Mutation: ignore the inspected start count and return self.limit from remaining().
    #[test]
    fn custody_cli_budget_nonzero_start_admits_only_the_remainder_then_refuses() -> TestResult<()> {
        let plan = DailyBudgetPlan::inspect(&inspection(3), None, None)?;
        assert_eq!(plan.observed_count, 3);
        assert_eq!(plan.start_count, 3);
        assert_eq!(plan.remaining(), 5);
        for accepted in 1..=plan.remaining() {
            plan.verify_progress(&inspection(3 + accepted), accepted)?;
        }
        plan.verify_progress(&inspection(8), plan.remaining())?;
        assert!(
            plan.verify_progress(&inspection(9), plan.remaining()).is_err(),
            "an extra admission must fail the slice"
        );
        assert_eq!(plan.reset_at, 172_800);
        Ok(())
    }

    #[test]
    fn custody_cli_budget_full_prefix_has_no_admission_attempts() -> TestResult<()> {
        for count in [8, 9] {
            assert_eq!(DailyBudgetPlan::inspect(&inspection(count), None, None)?.remaining(), 0);
        }
        Ok(())
    }

    #[test]
    fn custody_cli_budget_retained_expired_count_is_not_charged_to_a_new_day() -> TestResult<()> {
        let mut value = inspection(8);
        value["observed_at"] = 172_800.into();
        let plan = DailyBudgetPlan::inspect(&value, None, None)?;
        assert_eq!(plan.observed_count, 8);
        assert_eq!(plan.start_count, 0);
        assert_eq!(plan.remaining(), 8);
        assert_eq!(plan.reset_at, 259_200);
        assert!(
            plan.verify_progress(&value, 1).is_err(),
            "the old window cannot masquerade as progress"
        );
        Ok(())
    }

    #[test]
    fn custody_cli_budget_requires_an_unambiguous_prefix_and_global_headroom() -> TestResult<()> {
        let mut value = inspection(3);
        let mut peer = value["rows"][1].clone();
        peer["prefix"] = "another-prefix".into();
        value["rows"].as_array_mut().ok_or("rows missing")?.push(peer);
        assert!(DailyBudgetPlan::inspect(&value, None, None).is_err());
        assert_eq!(DailyBudgetPlan::inspect(&value, Some("fixture-prefix"), None)?.remaining(), 5);
        assert!(DailyBudgetPlan::inspect(&value, Some("missing-prefix"), None).is_err());
        value["rows"][0]["count"] = 253.into();
        assert!(DailyBudgetPlan::inspect(&value, Some("fixture-prefix"), None).is_err());
        Ok(())
    }

    #[test]
    fn custody_cli_budget_empty_rows_are_zero_only_for_a_known_fresh_fixture() -> TestResult<()> {
        let empty = json!({"observed_at":100_000,"rows":[]});
        assert!(DailyBudgetPlan::inspect(&empty, None, None).is_err());
        assert_eq!(DailyBudgetPlan::inspect(&empty, None, Some(8))?.remaining(), 8);
        assert!(DailyBudgetPlan::inspect(&empty, Some("fixture-prefix"), Some(8)).is_err());
        Ok(())
    }
    #[test]
    fn custody_prefix_quota_hint_requires_scope_and_the_durable_reset() -> TestResult {
        let status = serde_json::json!({"networking_reason":{"kind":"node_busy",
            "capacity":{"scope":"prefix_daily","resets_at_unix":172_800}}});
        require_daily_capacity_hint(&status, 172_800)?;
        assert!(require_daily_capacity_hint(&status, 259_200).is_err());
        let mut wrong_scope = status.clone();
        wrong_scope["networking_reason"]["capacity"]["scope"] = "global_daily".into();
        assert!(require_daily_capacity_hint(&wrong_scope, 172_800).is_err());
        assert!(require_daily_capacity_hint(&serde_json::json!({}), 172_800).is_err());
        Ok(())
    }
}
