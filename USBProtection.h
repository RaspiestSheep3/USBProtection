// USBProtection.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <iostream>

// TODO: Reference additional headers your program requires here.
#include <windows.h>
#include <dbt.h>
#include <initguid.h>
#include <usbiodef.h> // Contains GUID_DEVINTERFACE_USB_DEVICE
#include <string>
#include <fstream>
#include <algorithm>
#include <vector>
#include <ctime>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/applink.c>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <cfgmgr32.h>
#pragma comment (lib, "cfgmgr32.lib")