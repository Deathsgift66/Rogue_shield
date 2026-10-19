# RogueShield acceptable-use and safety policy

RogueShield is designed to help developers, maintainers and authorized security professionals evaluate and improve their own software and infrastructure.

## Authorized use

Before any network-connected test, the operator must affirm that they own the target or have explicit permission from an authorized owner; that the target and planned methods are within the granted scope; and that they understand the potential for outages, data exposure or unintended changes. Testing must comply with applicable law and contractual obligations.

## Restricted actions in the official tool

The maintainers' official builds are intended to reject or avoid unauthorized discovery, arbitrary third-party scanning, credential attacks, evasion, persistence, destructive testing, uncontrolled exploit execution and deliberate resource exhaustion. No arbitrary-target attack mode is planned.

The initial public build is offline-only. Future network features must be independently scope-enforced, use narrow request budgets, keep credentials confidential and favor disposable test fixtures.

## Safety model

1. Offline analysis is the default; no target host is inferred from source files.
2. Network testing, if added later, requires explicit target authorization, environment selection, permitted actions and bounded runtime limits.
3. Public production systems should be limited to clearly defined passive or offline assessments; privileged or modifying tests belong in an isolated, disposable environment.
4. Simulated swarms must remain entirely local and synthetic by default. An input such as `700 agents` is **not** permission to send 700 live clients to a real target.
5. Findings, results and logs must exclude credentials, identifying personal information and private test data.
6. Any model-assisted planner may suggest review tasks only; deterministic application code, not the model, must enforce permissions.

## Operator responsibility and limitations

A click-through acknowledgment is not proof of ownership, authorization or lawful behavior. Operators remain responsible for obtaining the necessary permissions, configuring targets correctly and using the software lawfully. The maintainers cannot guarantee that software safeguards prevent misuse, particularly when users can change independently distributed source code.

RogueShield is offered under the MIT License, which disclaims warranties and limits liability to the extent provided by its text and applicable law. No policy or license can categorically eliminate every possible legal claim. This document is an engineering and project-use policy, not individualized legal advice. It does not override the MIT License's permission grants for code distributed under it.
