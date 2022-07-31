# relay_multicast
A simple Python 2 script that shuffles specified Multicast/Boradcast-addresses to and from specified network-interfaces

This project was intended to get a functional process that relays multicast/broadcast packets between different interfaces on my Ubiquiti ER-X
as I've split up my home network into several Vlans I was loosing some function that new IoT-devices needed. 

As I could install python on the router the task was to make a functional script. The choosing of Python 2 instead of Python 3 is because the ER-X only supported the module "netifaces" on that version.

This is a working script that does it's job and can be called from a shell-script at boot to run in background as a fork-process.

For IoT devices that rely on ex. SSDP, mDNS and broadcasts etz.... This solves those problems...
