# Atal

An endpoint detection and response system which is engineered to be soft on your systems and your security teams.

A huge shoutout to [Kraken](https://github.com/botherder/kraken) which is my original inspiration to start this project.

## Goals

The goal here is to build a modern endpoint detection and response system which is capable for performing routine system scans, remediation of malicious files, etc.

**What makes us different?**

1. Reducing memory and cpu footprint on your systems through modern languages and better programming practices.
2. The fact that we pay extra attention to minimizing alert fatigue.
3. We utilize a coarse AI system *(fine tuning is pending)* for scanning files just to ensure that the system doesnt miss files not in strict yara rules.

The project is a gift from a developer for other developers. I know we all hate alerts which seem to never stop and I have paid special care to avoid reporting unwanted things.

### Roadmap

1. **Phase 1: Build a Detection System**
    1. Build a file scanner
    2. Build a process scanner
    3. Build a autorun scanner
    4. Achieve cross platform support.
    5. Add local persistence through sqlite.
    6. Add automated password management for local system users.
    7. Add automated lynis like system auditing.

2. **Phase 2: Sync with Remote Server**
    1. Build a Remote server capable of storing data collected.
    2. Build a feature to sync local data routinely.
    2. Build a feature for remote configurations and software updates.

3. **Phase 3: Build a Response System**
    1. Build quanratining feature.
    2. Build automated response feature.
    3. Build a feature to fetch virus samples from remote servers on demand.

4. **Phase 4: Build a Network Monitoring System**
    1. Add feature for controlling local firewalls remotely
    2. Add feature for logging network activity and scan it in runtime

5. **Phase 5: Add a feature to monitor log files**
    1. Monitor local system log files and scan them for any malicious activities by provided user rules.
    2. Become a full fledged Mitre attack scanner for the filesystem.

6. **Phase 6: Research and Development**
    1. Develop a data leak detection and stopping system