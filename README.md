# YourMalwareCompanion
YourMalwareCompanion (YMC) is a plug-and-play, customizable and extendable Windows driver that brings your malware capabilities to kernel land.

### Features
| |Feature       | Tested Windows Versions |     
|-|--------------|-------------------------|
|✅|Add/Remove process protection |  10 (19045) |
|✅|Set arbitrary process privileges |  10 (19045) |
|✅|List and delete process callbacks|  10 (19045) |
|✅|List and delete thread callbacks|  10 (19045) |
|✅|List and delete image callbacks|  10 (19045) |

## Build Requirements
- Visual Studio 2022.
- Latest Windows SDK (my version is 10.0.20348.0) and latest MSVC x64/x86 Spectre mitigation libraries (my version is v14.36-17.6), to be installed using Visual Studio Installer -> Individual Components.
- Latest Windows Driver Kit (WDK). Download it [here](https://go.microsoft.com/fwlink/?linkid=2196230). During the installation, ensure the checkbox for installing the Visual Studio extension is selected.

## Test
- Run the following command as an administrator to enable test signing mode:
```powershell
 bcdedit /set testsigning on
```
- Drop the .sys file on disk, for example under C:\YMC. Then, you need to create and start a service like this:
```powershell
 sc create YMC type= kernel binPath= C:\YMC\YMC.sys
 sc start YMC
```

You're ready to go! Compile and run the ExampleClient to test the various features of the driver. The client implementation is straightforward, so to understand how it works, just explore its code.

## Integrate

## Extend

## Credits
[Zero-Point Security: Offensive Driver Development](https://training.zeropointsecurity.co.uk/courses/offensive-driver-development)
