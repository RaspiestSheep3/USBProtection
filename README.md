# Hlin - A USB Protection Daemon

## Overview
Hlin is an open-source **USB Protection system** that scans USBs and blocks unwanted ones. It is designed to provide a **USB black-box** tracking changes and to **stop unauthorised USB plugins** on servers. 

---

## Features

- **Black-box tracking**
All changes are encrypted in a log on the USB which only the owner can access,
allowing for security and privacy

- **Customisable Policy**
USB plugin denials and requests can be automated through a customisable policy, which is parsed using an AST

- **Cryptographic Verification**
USBs are cryptographically verified with RSA and SHA256, so the owner can easily be tracked

- **OS-Level Integration**  
Windows integration means all USB updates are handled at the OS level, so the USB is fully ejected from the entire system and properly monitored

---

## Architecture Overview

- **C++** is used throughout the entire project for the daemon
- A custom language is used for the policy, with the extension ***.plc***

---

## Learning Results

- I learnt to work with **low-level Windows integration** in C++

- I improved my ability to implement **cryptographic protocols and concepts** in C++ through OpenSSL

- I learnt about **ASTs and compiler design**
--- 

## Future Improvements

- Support for **non-Windows** OSs

- **GUI** for easier UX

- **Networking** in order to track multiple USBs from one point