# KQL Hierarchy  

1. Cluster  
2. Database  
3. Table  
   3.1. Fields (raw-data)  

---

# Statements: where | pipe | take  

1. **where** → to point / specify a table  
2. **pipe** → we use *pipe* (`|`) to write more statements  
3. **take** → pick random rows / data in a table  

**Example Code:**  
```kql
Customers
| where FirstName == "Peter"
| where ContinentName == "Asia"
| where Education == "Bachelors"

Products
| take 10

cluster('help').database('SampleMetrics').Alerts
| take 20
```

---

# Syntax and Query Structure  

**Comparison Operators:**  
- `==` → exact match  
- `!=` → does not include  
- `=~` → case-insensitive match (eg: "Peter" == "peter")  

---

# Statements: contains | has | startswith | endswith  

1. **contains** → checks if a string has another string inside it  
2. **has** → like *contains* but matches whole words only  
3. **startswith** → checks if a string begins with specified words / char / number  
4. **endswith** → checks if a string ends with specified words / char / number  

> add `!` → eg = `!contains`, `!has`, `!startswith`, `!endswith` (does not include)  
> add `_cs` → eg = `contains_cs`, `has_cs`, `startswith_cs`, `endswith_cs` (force case-sensitive search)  

**Example Code:**  
```kql
SecurityEvent
| where Account contains "admin"
| where Computer has "Server01"
| where Account startswith "sys"
| where Account !endswith "guest"
```

---

# Statements: distinct | count | sort by | order by  

1. **distinct** → gets unique values and removes duplicates  
2. **count** → counts rows  
3. **sort by** → sort by columns (eg = ascending/descending order)  
4. **order by** → same as *sort by* (useful for SQL background)  

**Example Code:**  
```kql
SigninLogs
| distinct UserPrincipalName

SecurityEvent
| count

Users
| sort by Age desc

Users
| order by Name asc
```

---

# Statements: project | Numbers | Log Analytics  

1. **project** → show only selected fields but don’t remove duplicates  
2. **project-reorder** → show selected fields first but keep others too  
3. **project Users=Names** → rename `Names` field to `Users`  

**Example Code:**  
```kql
Usage
| where Quantity >= 10
| project Quantity, Unit = QuantityUnit, DataType
```

> Operators: `>=`, `<=`, `>`, `<` → eg: `Quantity >= 10`  

---

# Statements: top | and | or | limit  

1. **top** → returns the top N rows based on a sort column (not random)  
2. **and** → combines two conditions; both must be true  
3. **or** → combines two conditions; at least one must be true  
4. **limit** → works same as *take*  

**Example Code:**  
```kql
Products
| top 5 by Price desc

Customers
| where Country == "India" and Age > 25

Customers
| where Country == "India" or Country == "USA"

Products
| limit 10
```

---

# Statements: between | ago | now  

1. **between** → filters values within a range  
2. **ago** → represents a time offset from the current time  
3. **now** → displays the data in the current date and time  

> UTC, EST, IST → change timezone as needed (eg: `now(-4h)` == IST)  

**Example Code:**  
```kql
SecurityEvent
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-12))

SigninLogs
| where TimeGenerated > ago(7d)

Heartbeat
| where TimeGenerated <= now()
```

---

# Statements: extend | getschema | search  

1. **extend** → adds new calculated columns to the result  

**Example Code:**  
```kql
Usage
| extend GB = Quantity / 1000   // create new column GB
```

2. **getschema** → shows the schema (columns + types) of a table  

```kql
Usage
| getschema
```

3. **search** → finds a value across all tables and columns  

```kql
search "microsoft.com"
search in (Website, Domain) "google"
```

---

