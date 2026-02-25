## SHIELDX 

ShieldX is a Windows-based cybersecurity tool built to find security weaknesses and possible threats in real systems.

It is made for learning, research, and defensive security testing. The goal of ShieldX is simple. Give visibility. Show what is exposed. Help understand what could be abused. It is not built as a heavy enterprise product. It is built to understand security from the ground level.


## MODULES 

- Phishing Link Detection

This module analyzes URLs and domains to detect phishing attempts. It checks suspicious patterns, domain tricks, TLS problems, and other indicators commonly used in phishing attacks.

- Network Threat Monitor 

This module captures and analyzes live network traffic to detect suspicious or unusual behavior. It identifies anomalies such as scanning activity and potential threats  in real time.

- Malware Analysis

This module examines suspicious files to understand their behavior and possible threat capabilities. It focuses on revealing what a file can do rather than simply labeling it as malicious.


## REQUIREMENTS 

Windows 10 or newer

Git

Make

PowerShell

Java JDK 17 or newer

Python 3.10 or newer

Rust toolchain including rustc and cargo

GCC or MinGW-w64

NSIS 
- Python packages required

requests

scapy

psutil

colorama

pyyaml

python-whois


## INSTALLATION

Clone the repository:

```bash
git clone https://github.com/jahanzaibmir/ShieldX
cd ShieldX
```

## COMPILATION

- Rust Engine
```bash
cd services/misconfig/engine
cargo build --release
```

- C
```bash
cd services/misconfig/collectors/c
make
```

- Java (UI)
```bash
cd gui/java/src
javac shieldx/ui/Main.java
```

## RUNNING THE APPLICATION 

```bash
java shieldx.ui.Main
```

## INSTALLER USAGE

A build script is included to generate a Windows setup executable for hasle-free use

```

ShieldX_Setup.exe is already provided so you don't need to waste your precious clicks!!!

                        OR you can do it manually

Double-click the build_installer file and click RUN

ShieldX_Setup.exe gets generated

```

## PLATFORM SUPPORT

ShieldX is supports Windows only

## PROJECT STATUS

ShieldX is under active development.
Features, detection logic, and performance improvements are continuously being refined.
Updates are dropped regurarly.

## AUTHOR 

Jahanzaib Ashraf Mir

ShieldX, built with frustration, desire and enthusiasm!!!
