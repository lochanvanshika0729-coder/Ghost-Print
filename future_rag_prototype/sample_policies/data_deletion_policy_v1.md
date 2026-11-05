---
name: Illustrative Personal Data Deletion Policy
source_reference: sample_policies/data_deletion_policy_v1.md
version: 1.0
effective_date: 2025-01-01
jurisdiction: Global
---
# Purpose and scope
ILLUSTRATIVE SAMPLE ONLY — this document is fictional and is not a law, legal opinion, or statement of current regulatory requirements. It demonstrates how a maintainable policy knowledge base could be organized.

## Request validation
Before planning a deletion, confirm that the request is authorized and identify the person using current and historical identifiers supported by trusted records. A workflow status or an operation result is a claim about process execution; it is not proof of the current state of every resource.

## Resource discovery
Create an inventory of relevant resources and copies. Consider primary databases, regional replicas, reporting stores, search indexes, analytics exports, application logs, support attachments, caches, archives, backups, and third-party processors. Record which evidence supports each observation, when it was captured, and which identity reference it supports. Do not infer a resource relationship from a shared system label alone.

## Required treatment
For each resource, consult the applicable policy and decide whether the record should be removed, redacted, anonymized, or retained. If retention is required, preserve only the permitted fields, record the retention reason and end date when available, and keep the record protected from ordinary use. A retained tombstone may use a stable internal reference only when an applicable policy permits it; direct identifiers should be treated according to their specific rules.

## Verification and recreation paths
Check the state at the requested audit cutoff using evidence from the resource. Also inspect active synchronization, import, replication, backup, and restore paths that could recreate data. A deletion review should distinguish completed checks from future remediation and should not describe a proposed action as already performed.
