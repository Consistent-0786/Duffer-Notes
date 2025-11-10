# Definition : Splunk Index Time Process

- It is the stage between when data is received and when it is written to disk, during which it is parsed, broken into events, and key fields like timestamps are extracted
- This allows for faster searches later, as the extracted information is stored with the raw data from the start
- **It has Three Phases :**
	1. Input Phase
	2. Parsing Phase
	3. Indexing Phase
## Phase Table

| **Phase**             | **Handled At**                               | **Main Tasks**                                                                                                                                                                                                                                                                                                                                                                                       | **Details / Notes**                                                                                     |
| --------------------- | -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| **1. Input Phase**    | • Universal Forwarder      • Heavy Forwarder | • Open and read data sources (logs, files, network streams, etc.)                                   • Apply configurations to entire data streams                                                          • Send raw data for indexing                                                                                                                                                              | • Focus on **data collection and forwarding**              • No event breaking or field extraction here |
| **2. Parsing Phase**  | • Indexer        • Heavy Forwarder           | • Break raw data into **individual events**       • Extract **metadata fields**:                                • `host`                                                        • `source`                                                     • `sourcetype`                                             • `index` (defaults to _main_)                         • Identify or create **timestamps** | • Converts raw stream into structured events     • Prepares data for indexing                           |
| **3. Indexing Phase** | • Indexer                                    | • Write parsed data to **disk**                           • Run **license meter** to track indexed volume                                                          • Build **index data structures** for fast search                                                                                                                                                                                 | • Data becomes **searchable**              • Stored in **index buckets**                                |
## Summary  

`Input → Parsing → Indexing`  
**Raw data → Structured events → Searchable index**



