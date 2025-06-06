<h1 align="center">
 R00T SHAD0W 
</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Bash-Script-green?style=for-the-badge&logo=gnubash" />
  <img src="https://img.shields.io/badge/HACKING-R00T%20Shadow-blueviolet?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Interactive-Terminal-yellow?style=for-the-badge" />
</p>


![image](https://github.com/user-attachments/assets/23ce1db5-44e1-45c4-b7fa-44824504af50)

---

## About

`root-shadow.sh` is a modular, interactive and scriptable Linux enumeration framework built specifically for post-exploitation, CTFs, and real-world Red Team privilege escalation scenarios.  

Built with bash and crafted from the trenches of offensive security, it covers all core areas of local enumeration—without requiring any external connectivity.

## Key Features

- System: Kernel, modules, boot params, runlevels.
- Environment: User info, variables, shells, Python paths, password policies.
- Users & Groups: Privileged users, sudo configs, group memberships, SSH keys.
- Services: Running processes, Docker/LXC detection, logrotate configs.
- Jobs/Tasks: Cron, anacron, systemd timers.
- Networking: Interfaces, routing, DNS, ARP, listening services.
- Software: Versions of sudo, MySQL, PostgreSQL, Apache, compilers, linked libs.
- Interesting Files: SUID/SGID, POSIX capabilities, .bash_history, AWS keys, .git-credentials.

All output is color-coded, neatly formatted, and designed for offline ops.

## Usage

![image](https://github.com/user-attachments/assets/7a373759-4bbd-4436-ac24-217f35d50371)



```bash
./root-shadow.sh [options] [arguments]
```

### Options

| Flag | Description                    |
|------|--------------------------------|
| `-o` | Interactive selection menu     |
| `-s` | System enumeration             |
| `-e` | Environment enumeration        |
| `-u` | Users & Groups                 |
| `-v` | Services                       |
| `-j` | Jobs / Tasks (Cron, systemd)   |
| `-n` | Networking (IPs, ports, ARP)   |
| `-w` | Software                       |
| `-f` | Interesting Files              |

## Examples

```bash
./root-shadow.sh -s        # System info
./root-shadow.sh -e        # Environment info
./root-shadow.sh -u        # Users & Groups
./root-shadow.sh -o        # Interactive menu
```

## Interactive Mode

```bash
./root-shadow.sh -o
```

Displays an interactive panel:

![image](https://github.com/user-attachments/assets/b25d93aa-9d86-4b5f-96c8-be1c2f95b7a1)


## Designed For

- Red Team Post Exploitation
- CTF Privilege Escalation
- Lab Automation
- Offline Recon (No network required)
- Rooting misconfigured systems

## Why Use This?

- Fully offline — no external tools needed
- Interactive and scriptable
- Focused on privilege escalation
- Modular structure — extend as needed

## Requirements

- Bash
- Standard GNU/Linux tools (no dependencies)

## Credits

Crafted by **r4venn**  
Inspired by tools like `linenum.sh`, `LinPEAS`, and the grind of red teaming real boxes.


## License

MIT License

> Stay sharp, stay stealthy.

