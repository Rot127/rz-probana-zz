<!-- SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org> -->
<!-- SPDX-License-Identifier: LGPL-3.0-only -->

# Glossary

## BDA

### Post-Analysis

| Variable/Abbreviation | Long name | Definition | Meaning/Usage |
|-------------|-----------|------------|---------------|
| DEP | Dependencies | `Address →  { Address }` | Maps `memory_read` instructions to `memory_write` instructions which write its value. |
| KILL | Kill | `Address →  { Address }` | Maps `memory_write` instructions to other `memory_write` instructions it invalidates. E.g. because it overwrites the value definition of one of those. E.g.: Instruction `A` writes to `0x100`, later instruction `B` writes to `0x100`. Instruction `B` kills `A` when executed. |
