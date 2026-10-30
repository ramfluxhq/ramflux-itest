// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! One absolute slice deadline and bounded, observable convergence waits.
use super::TestResult;
use std::{cell::RefCell, future::Future, time::Duration};
use tokio::time::Instant;

// realnet.yml gives a slice 45 minutes, including fixture prebuild/startup.
// Keep five minutes for daemon cleanup, failure logs and Compose teardown.
const SLICE_BUDGET: Duration = Duration::from_mins(45);
const CLEANUP_RESERVE: Duration = Duration::from_mins(5);
const FLOW_BUDGET: Duration = SLICE_BUDGET.saturating_sub(CLEANUP_RESERVE);
// The two round trips contain more than twenty network convergence checks.
// No single missing condition may consume the whole remaining slice budget.
const CONDITION_SHARE: u32 = 20;

tokio::task_local! {
    static ACTIVE: WaitBudget;
}

pub(super) struct WaitBudget {
    started: Instant,
    deadline: Instant,
    operation: RefCell<String>,
}

impl WaitBudget {
    pub(super) fn new(started: Instant) -> Self {
        Self {
            started,
            deadline: started + FLOW_BUDGET,
            operation: RefCell::new("account setup".into()),
        }
    }

    pub(super) async fn run(self, flow: impl Future<Output = TestResult>) -> TestResult {
        ACTIVE
            .scope(self, async {
                let deadline = ACTIVE.with(|budget| budget.deadline);
                tokio::time::timeout_at(deadline, flow).await.map_err(
                    |_| -> Box<dyn std::error::Error> {
                        ACTIVE
                            .with(|budget| {
                                format!(
                                    "k2b slice deadline exhausted: elapsed_ms={} waiting_for={}",
                                    budget.started.elapsed().as_millis(),
                                    budget.operation.borrow()
                                )
                            })
                            .into()
                    },
                )?
            })
            .await
    }
}

pub(super) fn operation(label: &str) {
    let _ = ACTIVE.try_with(|budget| {
        *budget.operation.borrow_mut() = label.into();
        eprintln!(
            "STEP: k2b elapsed_ms={} remaining_ms={} waiting_for={label}",
            budget.started.elapsed().as_millis(),
            budget.deadline.saturating_duration_since(Instant::now()).as_millis()
        );
    });
}

pub(super) fn condition<T>(
    label: &str,
    future: impl Future<Output = TestResult<T>>,
) -> impl Future<Output = TestResult<T>> {
    // Box before constructing the returned future: nested bus and convergence
    // operations otherwise accumulate large inline state machines.
    let future = Box::pin(future);
    async move {
        let started = Instant::now();
        let deadline = ACTIVE.with(|budget| {
            let remaining = budget.deadline.saturating_duration_since(started);
            (started + remaining / CONDITION_SHARE).min(budget.deadline)
        });
        operation(label);
        let result = tokio::time::timeout_at(deadline, future).await.map_err(|_| {
        ACTIVE.with(|budget| format!(
            "k2b condition deadline exhausted: condition={label} allowed_ms={} elapsed_ms={} waiting_for={}",
            deadline.saturating_duration_since(started).as_millis(),
            started.elapsed().as_millis(), budget.operation.borrow()
        ))
    })?;
        eprintln!(
            "STEP: k2b condition_complete={label} elapsed_ms={} success={}",
            started.elapsed().as_millis(),
            result.is_ok()
        );
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn late_group_close_can_converge_after_the_old_flow_timeout() -> TestResult {
        let budget = WaitBudget::new(Instant::now());
        budget
            .run(async {
                tokio::time::sleep(Duration::from_secs(355)).await;
                condition("group close v4", async {
                    tokio::time::sleep(Duration::from_secs(37)).await;
                    Ok(())
                })
                .await
            })
            .await
    }

    #[tokio::test(start_paused = true)]
    async fn missing_condition_reports_the_pending_operation_within_its_share() -> TestResult {
        let started = Instant::now();
        let error = WaitBudget::new(started)
            .run(async {
                condition("group close v4", async {
                    operation(
                        "account=human method=message.receive surface=surface-group version=4",
                    );
                    std::future::pending::<TestResult>().await
                })
                .await
            })
            .await
            .err()
            .ok_or("missing condition unexpectedly completed")?;
        assert_eq!(started.elapsed(), FLOW_BUDGET / CONDITION_SHARE);
        let error = error.to_string();
        assert!(error.contains("condition=group close v4"), "{error}");
        assert!(error.contains("method=message.receive"), "{error}");
        assert!(error.contains("version=4"), "{error}");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn successive_conditions_do_not_reset_the_slice_deadline() -> TestResult {
        let started = Instant::now();
        let error = WaitBudget::new(started)
            .run(async {
                tokio::time::sleep(FLOW_BUDGET.saturating_sub(Duration::from_secs(20))).await;
                condition("late version", async {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Ok(())
                })
                .await
            })
            .await
            .err()
            .ok_or("condition ignored the remaining slice budget")?;
        assert!(error.to_string().contains("allowed_ms=1000"), "{error}");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn exhausted_slice_reports_the_current_operation() -> TestResult {
        let started = Instant::now();
        let error = WaitBudget::new(started)
            .run(async {
                operation("phase=group_restart conversation=group_thread_k2b");
                std::future::pending::<TestResult>().await
            })
            .await
            .err()
            .ok_or("slice deadline was ignored")?;
        assert_eq!(started.elapsed(), FLOW_BUDGET);
        assert!(error.to_string().contains("phase=group_restart"), "{error}");
        Ok(())
    }

    #[test]
    fn slice_budget_matches_the_hosted_workflow() {
        let workflow = include_str!("../../../.github/workflows/realnet.yml");
        assert!(
            workflow
                .split("  slice:")
                .nth(1)
                .is_some_and(|slice| slice.contains("timeout-minutes: 45"))
        );
        assert_eq!(SLICE_BUDGET, Duration::from_mins(45));
    }
}
