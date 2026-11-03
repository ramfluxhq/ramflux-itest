<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (c) 2026 Span Brain -->

# Changelog

## Unreleased

- Read protocol fixtures from the pinned product package resolved by offline Cargo metadata,
  independently of sibling checkouts.

- Upgrade Ed25519 to dalek 3 and pin the eight product dependencies to the matching
  crypto graph while preserving the frozen integration-node signature bytes.
