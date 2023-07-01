![Supported Python versions](https://img.shields.io/badge/python-3.10+-blue.svg) [![Twitter](https://img.shields.io/twitter/follow/al3x_n3ff?label=al3x_n3ff&style=social)](https://twitter.com/intent/follow?screen_name=al3x_n3ff)
# wsuks
_Weaponizing the WSUS Attack_

Becoming local Admin on a domain joined Windows Machine is usually the first step to obtain domain admin privileges in a pentest. To utilize the WSUS attack automatically this Tool spoofs the ip address of the WSUS-Server inside the network via arp and serves its own Windows Update as soon as the client requests them.
Per Default a Windows Client requests Updates every 24h. On request wsuks provides its own "Updates" executing Powershell commands on the target to create an local Admin and add it to the local Administrators group.

The served executable (Default: PsExec64.exe) as well as the executed command can be changed as needed.

## Installation
Using pipx:
```
sudo apt install python3-pipx git
sudo pipx ensurepath
sudo pipx install wsuks
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
sudo -i
wsuks
wsuks -t 10.0.0.10 --WSUS-Server 10.0.0.20
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

