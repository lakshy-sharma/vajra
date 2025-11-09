# TODO

## Near Term Focus

1. Add support for scanning running executables
2. Add support for autorun scanning before they execute.

## Project Roadmap

1. **Phase 1: Build a Detection System**
    1. Build a yara file scanner **(Done)**
    2. Build a yara based process scanner **(Done)**
    3. Build a autorun scanner to fid auto start services on any system. **(Done)**
    4. Add local persistence through sqlite. **(Done)**
    5. Add automated password management for local system users.
    6. Add automated lynis like system auditing.
    7. Add eBPF based syscall monitoring. **(Partially Done)**

2. **Phase 2: Sync with Remote Server**
    1. Build a remote server capable of storing data collected.
    2. Build a feature to sync local data routinely.
    2. Build a feature for remote configurations and software updates.

3. **Phase 3: Build a Response System**
    1. Build a quarantining feature.
    2. Build automated response feature.
    3. Build a feature to fetch malicious samples from remote servers on demand.

4. **Phase 4: Build a Network Monitoring System**
    1. Add feature for controlling local firewalls remotely
    2. Add feature for logging network activity and scan it in runtime

5. **Phase 5: Add a feature to monitor log files**
    1. Monitor local system log files and scan them for any malicious activities by provided user rules.
    2. Become a full fledged Mitre attack scanner for the filesystem.

6. **Phase 6: Research and Development**
    1. Develop a data leak detection and stopping system.
    2. Achieve complete cross platform support.