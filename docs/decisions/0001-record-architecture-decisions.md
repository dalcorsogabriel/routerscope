# 1. Record architecture decisions

- Status: accepted
- Date: 2026-11-27

## Context

routerscope is a public, community-driven project. Contributors join at different times and need to understand why the code is the way it is without reading every past discussion.

## Decision

We record significant decisions as short Architecture Decision Records (ADRs) in `docs/decisions/`, numbered sequentially (`NNNN-title.md`), following Michael Nygard's format: Context, Decision, Consequences.

A decision is "significant" when it changes the architecture, a public API of a published package, the license or dependency policy, the storage format, or a non-intrusion/security guarantee.

ADRs are immutable once accepted. To change a decision, write a new ADR that supersedes the old one and update the old one's status to `superseded by NNNN`.

## Consequences

- Each PR that makes a significant decision includes an ADR.
- The ADR index is the `Decisions` section of the docs site.
