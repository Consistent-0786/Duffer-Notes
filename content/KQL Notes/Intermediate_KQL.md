# Intermediate KQL Commands

---

# Data Types

| Data Type | Simple Explanation | Example |
|---|---:|---|
| `string` | Text: letters, numbers, symbols | `"Hello World"` |
| `int` | Whole number (32-bit) | `42` |
| `long` | Large whole number (64-bit) | `1234567890123` |
| `real` | Decimal number | `3.14`, `-99.99` |
| `bool` | Boolean true/false | `true`, `false` |
| `datetime` | Date and time value | `datetime(2023-01-01 12:00:00)` |
| `timespan` | Duration / time interval | `1.02:30:00` (1 day, 2.5 hours) |
| `dynamic` | JSON-like flexible structure | `dynamic({"name":"John","age":30})` |

> `string` empty vs others null:  
> - If a `string` column has no visible characters it's `""` (empty).  
> - Non-string columns with no value are `null`.  
>
> Helpers:  
> - Use `isnull()` / `isnotnull()` for non-string null checks.  
> - Use `isempty()` / `isnotempty()` for empty string checks.  
> - Cast between types with `tostring()`, `toint()`, `todouble()`, `datetime()` etc.

---

# summarize | count() | min | max | make_set

**`summarize`** — group rows and compute aggregations (like SQL `GROUP BY`).

- `count()` — total rows (use inside `summarize`).
- `min()` / `max()` — minimum / maximum values.
- `make_set()` — returns unique values for a column as an array (optionally limited).
- `bin()` — bucket timestamps or numbers into fixed intervals.
- `dcount()` — distinct (unique) count.
- `avg()` — average of numeric values.
- `countif()` — count rows that meet a condition inside `summarize`.

**Examples:**
```kql
// count of events per State
StormEvents
| summarize Events = count() by State

// earliest and latest event time per State
StormEvents
| summarize MinTime = min(EventTime), MaxTime = max(EventTime) by State

// unique list of states with events (limit 100)
StormEvents
| summarize States = make_set(State, 100)

// events per hour (bucketed)
StormEvents
| summarize Events = count() by bin(StartTime, 1h)

// distinct users per day
SigninLogs
| summarize UniqueUsers = dcount(UserPrincipalName) by bin(TimeGenerated, 1d)

// average damage amount by type
DamageLogs
| summarize AvgDamage = avg(DamageAmount) by DamageType

// conditional counts (number of events in Texas)
StormEvents
| summarize TexasEvents = countif(State == "Texas")
```

---

# render | timechart | areachart | barchart | piechart | etc

**`render`** — visualize query results. Use after `summarize` or when results are suitable for charting.

**Examples:**
```kql
// time-series chart of events per hour
StormEvents
| summarize Events = count() by bin(StartTime, 1h)
| render timechart

// bar chart of top 10 damage types
StormEvents
| summarize TotalDamage = sum(DamageAmount) by DamageType
| top 10 by TotalDamage
| render barchart
```

> Tip: The visualization name can be `timechart`, `barchart`, `areachart`, `piechart`, `columnchart`, `table`, etc. Some clients may prefer explicit options/styles.

---

# variables | let | pack_array | has_any | has_all

- `let` — declare reusable variables or subqueries.
- `pack_array()` — build an array (dynamic) from individual values.
- `has_any()` — true if any of the listed values appear in the column (or array).
- `has_all()` — true only if all listed values appear.

**Examples:**
```kql
// simple variable usage
let threshold = 10;
StormEvents
| where DamageCrops > threshold

// pack_array returns a dynamic array
print arr = pack_array("A", "B", "C")

// check if EventType contains any of multiple values
StormEvents
| where EventType has_any("Flood", "Hail")

// check if a dynamic array column contains all specified values
MyTable
| where Tags has_all("critical", "network")
```

---

# externaldata

`externaldata` — query data stored externally (e.g., Azure Blob Storage, public CSV).

**Example:**
```kql
externaldata (id:int, name:string)
[
  'https://myaccount.blob.core.windows.net/mycontainer/data.csv'
]
with (format='csv')
```

> Note: Access depends on cluster configuration, permissions, and allowed data sources.

---

# arg_max | round | union

- `arg_max()` — return the row(s) that have the maximum value for an expression (useful to pick the record with highest metric).
- `round()` — round numeric values.
- `union` — combine results from multiple tables.

**Examples:**
```kql
// returns the row (name) with the highest age
datatable(name:string, age:int) [ "Ali", 25, "Zara", 30 ]
| summarize arg_max(age, name)

// rounding
print x = round(3.67, 1)  // -> 3.7

// union two tables
union TableA, TableB
```

---

# join (kinds) — inner, leftouter, rightouter, fullouter, leftsemi, leftanti, rightsemi, rightanti, innerunique

`join` — combine rows from two tables based on matching keys. You can specify `kind=` to control behavior.

Example pattern (using `let` to store tables):
```kql
let _stormevents = database('Samples').table('StormEvents');
let _population  = database('Samples').table('PopulationData');
_population
| join kind=inner (_stormevents) on State
```

**Common `kind` values and short descriptions:**

| Join Kind | Description | Example |
|---|---|---|
| `inner` | Rows with matching keys from both tables | `T1 \| join kind=inner T2 on Id` |
| `innerunique` | Like `inner`, but de-duplicates left-side keys before joining | `T1 \| join kind=innerunique T2 on Id` |
| `leftouter` | All rows from left + matching rows from right | `T1 \| join kind=leftouter T2 on Id` |
| `rightouter` | All rows from right + matching rows from left | `T1 \| join kind=rightouter T2 on Id` |
| `fullouter` | All rows from both tables, matched where possible | `T1 \| join kind=fullouter T2 on Id` |
| `leftsemi` | Rows from left that have at least one match in right | `T1 \| join kind=leftsemi T2 on Id` |
| `leftanti` | Rows from left that do **not** match any row in right | `T1 \| join kind=leftanti T2 on Id` |
| `rightsemi` | Rows from right that have at least one match in left | `T1 \| join kind=rightsemi T2 on Id` |
| `rightanti` | Rows from right that do **not** match any row in left | `T1 \| join kind=rightanti T2 on Id` |

> Default behavior: when no `kind=` is specified Kusto uses `innerunique` semantics (de-duplicate left keys).  
> Use `$left` / `$right` qualifiers when you need to reference same column names from both sides:
> ```kql
> | join kind=inner (_sales) on $left.CustomerKey == $right.CustomerKey
> ```

---

# Additional tips & precision notes

- Prefer `summarize` + `bin()` for time-series aggregations before `render`.
- Use `project` / `project-away` / `project-rename` to shape results before aggregations or joins.
- When joining large tables, consider summarizing or reducing rows first to improve performance.
- `make_set()` and `make_list()` are useful for collecting values, but watch limits (you can pass a max-size parameter).
- `externaldata` and cross-cluster queries require correct network and security configuration.

