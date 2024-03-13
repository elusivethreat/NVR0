# NVR0
Nvidia Driver poc. This was developed last year when I was doing research and learning more about BYOVD, but the certificate was recently revoked so it's not being "archived" here for research and training purposes.

## Exploit Primitives
- Abuses MmMapIoSpace and MmGetPhysicalAddress

## Unique Requirements
- Unique IOCTL to reach ioctl_dispatcher function
- CmdBuff structure that stores CMD type, and args for different APIs etc..
- Buffer passed from usermode must contain a unique hash at a specific offset that uses 2 custom seeds to generate.

