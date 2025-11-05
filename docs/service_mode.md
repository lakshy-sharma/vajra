# Service Mode 

## Architecture

This is the complete architecture of service mode.

```
Start
|--> Setup Config and Database Handler -> Local Sqlite3 DB
|--> eBPF Event Generator
|       |
|       |--> Filesystem Event Handler
|       |--> Process Event Handler
|       |--> Memory Event Handler
|       |--> Network Event Handler
|
|--> Periodic Database Cleanup [Cron]
|--> Periodic Full Scans [Cron]
```