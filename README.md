# ShieldX

ShieldX is a Windows-based cybersecurity tool built to identify common security threats and system weaknesses in real-world environments.
It focuses on visibility, misconfiguration awareness, and early threat detection rather than heavy enterprise features.

The tool is designed for learning, research, and defensive security testing.

# Modules
 - Phishing Link Detection

Analyzes URLs to identify suspicious or potentially malicious links commonly used in phishing attacks.

 - Misconfiguration Detection

Scans the system and connected network to detect open ports, exposed services, and insecure configurations that increase attack surface.

 - Zero-Day Threat Detection

Monitors system and network behavior to identify anomalies that may indicate unknown or emerging threats.


# System Requirements

- Windows 10 or newer

- Git

- Make

- PowerShell

- Java JDK 17 or newer

- Python 3.10 or newer

- Rust toolchain (rustc and cargo)

- GCC or MinGW-w64

- Administrator privileges for some modules

- Pyhton Requirements ; 

requests
scapy
psutil
colorama
pyyaml
pyhton-whois

# How to set up

git clone  https://github.com/jahanzaibmir/ShieldX

cd ShieldX/

# Compile 

cd gui/java/src

javac shieldx/ui/Main.java

# Run it

java shieldx.ui.Main

# Platform Support

ShieldX currently supports Windows systems.
Some features may require administrative privileges.


# Project Status

ShieldX is under active development. I drop the daily updates to make it upto date and you satisfied

# Author

Developed by Jahanzaib Ashraf Mir 
Built with curiosity, frustration, and a desire to safegaurd systems from outside attacks.

