# Tsunami

Yet another Windows driver used to read and write memory from kernel.

It receives instructions from userland with IOCTLs and uses shared memory to communicate the bytes read and bytes to write.

## Building

This project has been tested to work on Windows 10, version 1803. It was built using WDK 10.

## Loading

The driver is designed to be "driverless" and able to be loaded through manual mapping by a tool such as drvmap, Turla Driver Loader, or kdmapper. 

It has been tested with drvmap.  

## Acknowledgments

* https://www.unknowncheats.me/
* Zer0Mem0ry's KernelBhop project
* mq1n's EasyRing0 project
