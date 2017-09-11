# Support statement for this release

This document describes the support status and in particular the
security support status of the Xen branch within which you find it.

See the bottom of the file for the definitions of the support status
levels etc.

# Release Support

    Xen-Version: 4.10-unstable
    Initial-Release: n/a
    Supported-Until: TBD
    Security-Support-Until: Unreleased - not yet security-supported

# Feature Support

## Host Architecture

### x86-64

    Status: Supported

### ARM v7 + Virtualization Extensions

    Status: Supported

### ARM v8

    Status: Supported

## Guest Type

### x86/PV

    Status: Supported

Traditional Xen Project PV guest

### x86/HVM

    Status: Supported

Fully virtualised guest using hardware virtualisation extensions

Requires hardware virtualisation support

### x86/PVH guest

    Status: Tech Preview

PVHv2 guest support

Requires hardware virtualisation support

### ARM guest

    Status: Supported

ARM only has one guest type at the moment

## Limits/Host

### CPUs

    Limit, x86: 4095
    Limit, ARM32: 8
    Limit, ARM64: 128

Note that for x86, very large number of cpus may not work/boot,
but we will still provide security support

### x86/RAM

    Limit, x86: 16TiB
    Limit, ARM32: 16GiB
    Limit, ARM64: 5TiB

[XXX: Andy to suggest what this should say for x86]

## Limits/Guest

### Virtual CPUs

    Limit, x86 PV: 512
    Limit, x86 HVM: 128
    Limit, ARM32: 8
    Limit, ARM64: 128

[XXX Andrew Cooper: Do want to add "Limit-Security" here for some of these?]

### Virtual RAM

    Limit, x86 PV: >1TB
    Limit, x86 HVM: 1TB
    Limit, ARM32: 16GiB
    Limit, ARM64: 1TB

### x86 PV/Event Channels

    Limit: 131072

## Toolstack

### xl

    Status: Supported

### Direct-boot kernel image format

    Supported, x86: bzImage
    Supported, ARM32: zImage
    Supported, ARM64: Image

Format which the toolstack accept for direct-boot kernels

### Qemu based disk backend (qdisk) for xl

    Status: Supported

### Open vSwitch integration for xl

    Status: Supported

### systemd support for xl

    Status: Supported

### JSON output support for xl

    Status: Experimental

Output of information in machine-parseable JSON format

### AHCI support for xl

    Status, x86: Supported

### ACPI guest

    Status, x86 HVM: Supported
    Status, ARM: Tech Preview

### PVUSB support for xl

    Status: Supported

### HVM USB passthrough for xl

    Status, x86: Supported

### QEMU backend hotplugging for xl

    Status: Supported

### Virtual cpu hotplug

    Status: Supported

## Toolstack/3rd party

### libvirt driver for xl

    Status: Supported, Security support external

## Debugging, analysis, and crash post-mortem

### gdbsx

    Status, x86: Supported

Debugger to debug ELF guests

### Guest serial sonsole

    Status: Supported

Logs key hypervisor and Dom0 kernel events to a file

### Soft-reset for PV guests

    Status: Supported
	
Soft-reset allows a new kernel to start 'from scratch' with a fresh VM state, 
but with all the memory from the previous state of the VM intact.
This is primarily designed to allow "crash kernels", 
which can do core dumps of memory to help with debugging in the event of a crash.

### xentrace

    Status, x86: Supported

Tool to capture Xen trace buffer data

### gcov

    Status: Supported, Not security supported

Export hypervisor coverage data suitable for analysis by gcov or lcov.

## Memory Management

### Memory Ballooning

    Status: Supported

### Memory Sharing

    Status, x86 HVM: Tech Preview
    Status, ARM: Tech Preview

Allow sharing of identical pages between guests

### Memory Paging

    Status, x86 HVM: Experimenal

Allow pages belonging to guests to be paged to disk

### Transcendent Memory

    Status: Experimental

[XXX Add description]

### Alternative p2m

    Status, x86 HVM: Tech Preview
    Status, ARM: Tech Preview

Allows external monitoring of hypervisor memory
by maintaining multiple physical to machine (p2m) memory mappings.

## Resource Management

### CPU Pools

    Status: Supported

Groups physical cpus into distinct groups called "cpupools",
with each pool having the capability of using different schedulers and scheduling properties.

### Credit Scheduler

    Status: Supported

The default scheduler, which is a weighted proportional fair share virtual CPU scheduler.

### Credit2 Scheduler

    Status: Supported

Credit2 is a general purpose scheduler for Xen,
designed with particular focus on fairness, responsiveness and scalability

### RTDS based Scheduler

    Status: Experimental

A soft real-time CPU scheduler built to provide guaranteed CPU capacity to guest VMs on SMP hosts

### ARINC653 Scheduler

    Status: Supported, Not security supported

A periodically repeating fixed timeslice scheduler. Multicore support is not yet implemented.

### Null Scheduler

    Status: Experimental

A very simple, very static scheduling policy 
that always schedules the same vCPU(s) on the same pCPU(s). 
It is designed for maximum determinism and minimum overhead
on embedded platforms.

### Numa scheduler affinity

    Status, x86: Supported

Enables Numa aware scheduling in Xen

## Scalability

### 1GB/2MB super page support

    Status: Supported

### x86/PV-on-HVM

    Status: Supported

This is a useful label for a set of hypervisor features
which add paravirtualized functionality to HVM guests 
for improved performance and scalability.  
This includes exposing event channels to HVM guests.

### x86/Deliver events to PVHVM guests using Xen event channels

    Status: Supported

## High Availability and Fault Tolerance

### Live Migration, Save & Restore

    Status, x86: Supported

### Remus Fault Tolerance

    Status: Experimental

### COLO Manager

    Status: Experimental

### x86/vMCE

    Status: Supported

Forward Machine Check Exceptions to Appropriate guests

## Virtual driver support, guest side

[XXX Consider adding 'frontend' and 'backend' to the titles in these two sections to make it clearer]

### Blkfront

    Status, Linux: Supported
    Status, FreeBSD: Supported, Security support external
    Status, Windows: Supported

Guest-side driver capable of speaking the Xen PV block protocol

### Netfront

    Status, Linux: Supported
    States, Windows: Supported
    Status, FreeBSD: Supported, Security support external
    Status, NetBSD: Supported, Security support external
    Status, OpenBSD: Supported, Security support external

Guest-side driver capable of speaking the Xen PV networking protocol

### Xen Framebuffer

    Status, Linux (xen-fbfront): Supported

Guest-side driver capable of speaking the Xen PV Framebuffer protocol

### Xen Console

    Status, Linux (hvc_xen): Supported
    Status, Windows: Supported

Guest-side driver capable of speaking the Xen PV console protocol

### Xen PV keyboard

    Status, Linux (xen-kbdfront): Supported
    Status, Windows: Supported

Guest-side driver capable of speaking the Xen PV keyboard protocol

[XXX 'Supported' here depends on the version we ship in 4.10 having some fixes]

### Xen PVUSB protocol

    Status, Linux: Supported

### Xen PV SCSI protocol

    Status, Linux: Supported, with caveats

NB that while the pvSCSU frontend is in Linux and tested regularly,
there is currently no xl support.

### Xen TPMfront

    Status, Linux (xen-tpmfront): Tech Preview

Guest-side driver capable of speaking the Xen PV TPM protocol

### Xen 9pfs frontend

    Status, Linux: Tech Preview

Guest-side driver capable of speaking the Xen 9pfs protocol

### PVCalls frontend

    Status, Linux: Tech Preview

Guest-side driver capable of making pv system calls

## Virtual device support, host side

### Blkback

    Status, Linux (blkback): Supported
    Status, FreeBSD (blkback): Supported
    Status, QEMU (xen_disk): Supported
    Status, Blktap2: Deprecated

Host-side implementations of the Xen PV block protocol

### Netback

    Status, Linux (netback): Supported
    Status, FreeBSD (netback): Supported

Host-side implementations of Xen PV network protocol

### Xen Framebuffer

    Status, Linux: Supported
    Status, QEMU: Supported

Host-side implementaiton of the Xen PV framebuffer protocol

### Xen Console (xenconsoled)

    Status: Supported

Host-side implementation of the Xen PV console protocol

### Xen PV keyboard

    Status, QEMU: Supported

Host-side implementation fo the Xen PV keyboard protocol

### Xen PV USB

    Status, Linux: Experimental
    Status, QEMU: Supported

Host-side implementation of the Xen PV USB protocol

### Xen PV SCSI protocol

    Status, Linux: Supported, with caveats

NB that while the pvSCI backend is in Linux and tested regularly,
there is currently no xl support.

### Xen PV TPM

    Status: Tech Preview

### Xen 9pfs

    Status, QEMU: Tech Preview

### PVCalls

    Status, Linux: Tech Preview

### Online resize of virtual disks

    Status: Supported

## Security

### Driver Domains

    Status: Supported

### Device Model Stub Domains

    Status: Supported, with caveats

Vulnerabilities of a device model stub domain to a hostile driver domain are excluded from security support.

### KCONFIG Expert

    Status: Experimental

### Live Patching

    Status, x86: Supported
    Status, ARM: Experimental

Compile time disabled

### Virtual Machine Introspection

    Status, x86: Supported, not security supported

### XSM & FLASK

    Status: Experimental

Compile time disabled

### XSM & FLASK support for IS_PRIV

    Status: Experimental

Compile time disabled

## Hardware

### x86/Nested PV

    Status, x86 HVM: Tech Preview

This means running a Xen hypervisor inside an HVM domain,
with support for PV L2 guests only
(i.e., hardware virtualization extensions not provided
to the guest).

This works, but has performance limitations
because the L1 dom0 can only access emulated L1 devices.

### x86/Nested HVM

    Status, x86 HVM: Experimental

This means running a Xen hypervisor inside an HVM domain,
with support for running both PV and HVM L2 guests
(i.e., hardware virtualization extensions provided
to the guest).

### x86/HVM iPXE

    Status: Supported, with caveats

Booting a guest via PXE.
PXE inherently places full trust of the guest in the network,
and so should only be used
when the guest network is under the same administrative control
as the guest itself.

### x86/HVM BIOS

    Status: Supported

Booting a guest via guest BIOS firmware

### x86/HVM EFI

	Status: Supported

Booting a guest via guest EFI firmware

### x86/Physical CPU Hotplug

    Status: Supported

### x86/Physical Memory Hotplug

    Status: Supported

### x86/PCI Passthrough PV

    Status: Supported, Not security supported

PV passthrough cannot be done safely.

[XXX Not even with an IOMMU?]

### x86/PCI Passthrough HVM

    Status: Supported, with caveats

Many hardware device and motherboard combinations are not possible to use safely.
The XenProject will support bugs in PCI passthrough for Xen,
but the user is responsible to ensure that the hardware combination they use
is sufficiently secure for their needs,
and should assume that any combination is insecure
unless they have reason to believe otherwise.

### ARM/Non-PCI device passthrough

    Status: Supported

### x86/Advanced Vector eXtension

    Status: Supported

### vPMU

    Status, x86: Supported, Not security supported

Virtual Performance Management Unit for HVM guests

Disabled by default (enable with hypervisor command line option).
This feature is not security supported: see http://xenbits.xen.org/xsa/advisory-163.html

### Intel Platform QoS Technologies

    Status: Tech Preview

### ARM/ACPI (host)

    Status: Experimental

### ARM/SMMUv1

    Status: Supported

### ARM/SMMUv2

    Status: Supported

### ARM/GICv3 ITS

    Status: Experimental

Extension to the GICv3 interrupt controller to support MSI.

### ARM: 16K and 64K pages in guests

    Status: Supported, with caveats

No support for QEMU backends in a 16K or 64K domain.

[XXX Need to go through include/public hypercalls to look for more features]

# Format and definitions

This file contains prose, and machine-readable fragments.
The data in a machine-readable fragment relate to
the section and subsection in which it is found.

The file is in markdown format.
The machine-readable fragments are markdown literals
containing RFC-822-like (deb822-like) data.

## Keys found in the Feature Support subsections

### Status

This gives the overall status of the feature,
including security support status, functional completeness, etc.
Refer to the detailed definitions below.

If support differs based on implementation
(for instance, x86 / ARM, Linux / QEMU / FreeBSD),
one line for each set of implementations will be listed.

### Restrictions

This is a summary of any restrictions which apply,
particularly to functional or security support.

Full details of restrictions may be provided in the prose
section of the feature entry,
if a Restrictions tag is present.

### Limit-Security

For size limits.
This figure shows the largest configuration which will receive
security support.
This does not mean that such a configuration will actually work.
This limit will only be listed explicitly
if it is different than the theoretical limit.

### Limit

This figure shows a theoretical size limit.
This does not mean that such a large configuration will actually work.

## Definition of Status labels

Each Status value corresponds to levels of security support,
testing, stability, etc., as follows:

### Experimental

    Functional completeness: No
    Functional stability: Here be dragons
    Interface stability: Not stable
    Security supported: No

### Tech Preview

    Functional completeness: Yes
    Functional stability: Quirky
    Interface stability: Provisionally stable
    Security supported: No

#### Supported

    Functional completeness: Yes
    Functional stability: Normal
    Interface stability: Yes
    Security supported: Yes

#### Deprecated

    Functional completeness: Yes
    Functional stability: Quirky
    Interface stability: No (as in, may disappear the next release)
    Security supported: Yes

All of these may appear in modified form.  There are several
interfaces, for instance, which are officially declared as not stable;
in such a case this feature may be described as "Stable / Interface
not stable".

## Definition of the status label interpretation tags

### Functionally complete

Does it behave like a fully functional feature?
Does it work on all expected platforms,
or does it only work for a very specific sub-case?
Does it have a sensible UI,
or do you have to have a deep understanding of the internals
to get it to work properly?

### Functional stability

What is the risk of it exhibiting bugs?

General answers to the above:

 * **Here be dragons**

   Pretty likely to still crash / fail to work.
   Not recommended unless you like life on the bleeding edge.

 * **Quirky**

   Mostly works but may have odd behavior here and there.
   Recommended for playing around or for non-production use cases.

 * **Normal**

   Ready for production use

### Interface stability

If I build a system based on the current interfaces,
will they still work when I upgrade to the next version?

 * **Not stable**

   Interface is still in the early stages and
   still fairly likely to be broken in future updates.

 * **Provisionally stable**

   We're not yet promising backwards compatibility,
   but we think this is probably the final form of the interface.
   It may still require some tweaks.

 * **Stable**

   We will try very hard to avoid breaking backwards  compatibility,
   and to fix any regressions that are reported.

### Security supported

Will XSAs be issued if security-related bugs are discovered
in the functionality?

If "no",
anyone who finds a security-related bug in the feature
will be advised to
post it publicly to the Xen Project mailing lists
(or contact another security response team,
if a relevant one exists).

Bugs found after the end of **Security-Support-Until**
in the Release Support section will receive an XSA
if they also affect newer, security-supported, versions of Xen.
However,
the Xen Project will not provide official fixes
for non-security-supported versions.

Three common 'diversions' from the 'Supported' category
are given the following labels:

  * **Supported, Not security supported**

    Functionally complete, normal stability,
    interface stable, but no security support

  * **Supported, Security support external**
  
    This feature is security supported
    by a different organization (not the XenProject).
    See **External security support** below.

  * **Supported, with caveats**

    This feature is security supported only under certain conditions,
    or support is given only for certain aspects of the feature,
    or the feature should be used with care
    because it is easy to use insecurely without knowing it.
    Additional details will be given in the description.

### Interaction with other features

Not all features interact well with all other features.
Some features are only for HVM guests; some don't work with migration, &c.

### External security support

The XenProject security team
provides security support for XenProject projects.

We also provide security support for Xen-related code in Linux,
which is an external project but doesn't have its own security process.

External projects that provide their own security support for Xen-related features are listed below.

  * QEMU https://wiki.qemu.org/index.php/SecurityProcess

  * Libvirt https://libvirt.org/securityprocess.html

  * FreeBSD https://www.freebsd.org/security/
  
  * NetBSD http://www.netbsd.org/support/security/
  
  * OpenBSD https://www.openbsd.org/security.html

 
