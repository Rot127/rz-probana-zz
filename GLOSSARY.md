# Glossary

## BDA

### Post-Analysis

| Variable/Abbrevation | Long name | Definition | Meaning/Usage |
|-------------|-----------|------------|---------------|
| DEP | Dependencies | `Address →  { Address }` | Maps `memory_read` instr. to `memory_write` instr. which write its value. |
| KILL | Kill | `Address →  { Address }` | Maps `memory_write` instr. to other `memory_write` instr. it invalidates. E.g. because it overwrites the value definition of one of those. E.g.: Instruction `A` writes to `0x100`, later instruction `B` writes to `0x100`. Instruction `B` kills `A` when executed. |
