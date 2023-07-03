![Supported Python versions](https://img.shields.io/badge/python-3.10+-blue.svg) [![Twitter](https://img.shields.io/twitter/follow/al3x_n3ff?label=al3x_n3ff&style=social)](https://twitter.com/intent/follow?screen_name=al3x_n3ff)
# wsuks
_Weaponizing the WSUS Attack_

Gaining local administrative access on a Windows machine that is part of a domain is typically the initial step towards acquiring domain admin privileges during a penetration test. In order to exploit the WSUS attack automatically, this tool spoofs the IP address of the WSUS server within the network using ARP, and when the client requests Windows updates, it provides its own malicious updates instead.
By default, a Windows client requests updates every 24 hours. 

Both the executable file served (Default: PsExec64.exe) and the executed command can be changed as needed.

Prerequisits:
- The target Client must be on the local network
- The Windows Server Update Service (WSUS) must be configured using HTTP

Result:
- After successful execution a user with the format user[0-9]{5} (e.g. user12345) and a random password will be created and added to the local admin group

## Installation
Using pipx:
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

With pipx:
```
sudo wsuks
suso wsuks -t 10.0.0.10 --WSUS-Server 10.0.0.20
```

With poetry:
```
sudo poetry run wsuks
sudo poetry run wsuks -t 10.0.0.10 --WSUS-Server 10.0.0.20
```

## About & Mitigation
In the [PyWSUS](https://github.com/GoSecure/pywsus) Repository from GoSecure you can find a great documentation how to you could detect and mitigate this attack.
They also wrote a great Guide demonstrating how this attack works in detail [here](https://www.gosecure.net/blog/2020/09/03/wsus-attacks-part-1-introducing-pywsus/).

This Tool is based on the following projects:
- https://github.com/GoSecure/pywsus
- https://github.com/GoSecure/wsuspect-proxy

