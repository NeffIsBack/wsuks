![Supported Python versions](https://img.shields.io/badge/python-3.9+-blue.svg) [![Twitter](https://img.shields.io/twitter/follow/al3x_n3ff?label=al3x_n3ff&style=social)](https://twitter.com/intent/follow?screen_name=al3x_n3ff)

# wsuks
_Automating the WSUS Attack_

Gaining local administrative access to a Windows machine that is part of a domain is typically the first step in gaining domain admin privileges during a penetration test. In many cases, the Windows Server Update Service (WSUS) is configured to deploy updates to clients over the local network using HTTP. Without the security of HTTPS, an attacker can mount a machine-in-the-middle attack to serve an update to the client, which will then execute with SYSTEM privileges. Any Microsoft signed executable can be served as an update, including a custom command with which the executable is executed.

To automatically exploit the WSUS attack, this tool spoofs the IP address of the WSUS server on the network using ARP, and when the client requests Windows updates, it serves PsExec64.exe with a predefined PowerShell script to gain local admin privileges. Both the executable file that is served (default: PsExec64.exe) and the command that is executed can be changed if required.\
By default, a Windows client will check for updates approximately every 24 hours.


Prerequisits:
- The target client must be on the local network
- The Windows Server Update Service (WSUS) must be configured using HTTP

Result:
- After successful execution the user provided will be added to the local admin group. If no user was specified a user with the format user[0-9]{5} (e.g. user12345) and a random password will be created

Implemented features:
 - [x] ARP spoofing the target
 - [x] Routing the ARP spoofed packets to the local HTTP server
 - [x] HTTP server to serve the malicious updates
 - [x] Automatic detection of the WSUS server
 - [x] Included PowerShell script and executable to gain local admin access

## Installation 🖥️
Using pipx (recommended):
```shell
sudo apt install pipx python3-nftables
pipx ensurepath
pipx install wsuks --system-site-packages
sudo ln -s ~/.local/bin/wsuks /usr/local/sbin/wsuks
```

Using poetry:
```shell
sudo apt install pipx git python3-nftables      # poetry should still be installed with pipx, but apt will work as well
sudo pipx install poetry
sudo ln -s /root/.local/bin/poetry /usr/local/sbin/poetry
git clone https://github.com/NeffIsBack/wsuks
cd wsuks
sudo poetry install
```

## Usage 🛠️
❗wsuks must be run as root❗

With pipx, you can just run `sudo wsuks ...` anywhere on the system.\
If you are using poetry, you must be in the wsuks folder and start each command with `sudo poetry run wsuks ...`

This tool requires the `nftables` package to be installed, which is the default on all debian based systems.\

There are 3 different modes/attack scenarios in which wsuks can be run, which are described below.
### Specify known WSUS Server and create local admin user:
If the WSUS server is already known, you can simply specify the target IP and the WSUS server IP.\
The default executable is PsExec64.exe, which runs a predefined PowerShell script with the following actions:
1. Create a new user of the format user[0-9]{5} (e.g. user12345) and a random password
2. Set the LocalAccountTokenFilterPolicy to 1 (disabling UAC ⚠)
3. Add the created user to the local admin group

⚠ Before setting the LocalAccountTokenFilterPolicy to 1, the original value is stored in the user description field so that it can be restored later

```shell
sudo wsuks -t 10.0.0.10 --WSUS-Server 10.0.0.20
```

### Specify known WSUS Server and add provided domain user to local admin group (domain is required!):
If you already have a domain user and you know the IP of the WSUS server, wsuks will simply add the user to the local Administrators group.
```shell
sudo wsuks -t 10.0.0.10 --WSUS-Server 10.0.0.20 -u User -d domain.local
```

### Autodiscover the WSUS Server by only specifying the domain user with the DC IP:
If you already have a domain user, wsuks will parse the GPOs on the domain controller to find the WSUS server.\
A PowerShell script is executed, which will add the provided domain user to the local admin group.
```shell
sudo wsuks -t 10.0.0.10 -u User -p Password -d domain.local --dc-ip 10.0.0.1
```

**Tipp:** If you only want to check for a WSUS server, you can use the `--only-discover` flag.

## Demo 🎥
Here is a short demo of the attack with a known WSUS server:
![Demo of the WSUS attack](media/wsuks-demo.gif)


## About & Mitigation 🛡️
In the [PyWSUS](https://github.com/GoSecure/pywsus) repository from GoSecure you can find a great documentation how you could detect and mitigate this attack.
They also wrote a great Guide demonstrating how this attack works in detail [here](https://www.gosecure.net/blog/2020/09/03/wsus-attacks-part-1-introducing-pywsus/).

Parts of this tool are based on the following projects:
- https://github.com/GoSecure/pywsus
- https://github.com/GoSecure/wsuspect-proxy

