# Linux Kernel `sysctl` Hardening

Last reviewed: September 2026, using current upstream documentation from [docs.kernel.org](https://docs.kernel.org/admin-guide/sysctl/index.html).

## Table of Contents

- [Scope](#scope)
- [Before you start](#before-you-start)
- [How sysctl configuration is loaded](#how-sysctl-configuration-is-loaded)
- [Local hardening](#local-hardening)
- [Network hardening for a non-routing host](#network-hardening-for-a-non-routing-host)
- [Settings that depend on the network](#settings-that-depend-on-the-network)
- [Optional restrictions](#optional-restrictions)
- [Restrictions that last until reboot](#restrictions-that-last-until-reboot)
- [Example configuration](#example-configuration)
- [Apply and verify the configuration](#apply-and-verify-the-configuration)
- [Roll back](#roll-back)
- [What changed from the old list](#what-changed-from-the-old-list)
- [References](#references)

## Scope

This guide targets a general-purpose home server that does not route traffic for other systems. It assumes IPv4 and IPv6 are both enabled.

Do not use the network section unchanged on a router, VPN gateway, hypervisor, Docker or Kubernetes host, or any other machine that forwards traffic. Those systems need a policy built around their actual topology.

The old version of this file collected settings from several hardening blogs. It mixed security controls with performance tuning, contained keys that no longer exist, and disabled useful TCP features. This version keeps settings with a clear security purpose and leaves workload tuning to the administrator.

These settings provide defense in depth. They do not replace kernel updates, a firewall, secure service configuration, or an active Linux Security Module such as AppArmor or SELinux.

## Before you start

Keep another root-capable session open while testing. A second SSH connection, serial console, or local console gives you a way back if a change interrupts networking or debugging.

Check every key before adding it to a config file:

```bash
sysctl kernel.kptr_restrict
```

If the command reports an unknown key, your kernel does not expose that setting. Leave it out. Availability depends on the kernel version, build configuration, architecture, and distribution patches.

Compare the current value with the recommendation as well. A static config file cannot express "at least this restrictive." Blindly writing a suggested value can weaken a stricter distribution default.

## How sysctl configuration is loaded

`sysctl -w` changes a running kernel. A config file makes the change persistent.

Local policy normally belongs in a drop-in such as:

```text
/etc/sysctl.d/90-server-hardening.conf
```

Files with the same name under `/etc/sysctl.d/` take precedence over files in lower-priority directories such as `/usr/lib/sysctl.d/`. The selected files are then processed in lexicographic order. A later file can override an earlier literal assignment. The name `90-server-hardening.conf` is usually late enough for local policy, but check the files already installed on your system.

Loader behavior differs in one important place:

- `systemd-sysctl` does not read `/etc/sysctl.conf` directly, although some distributions link that file into `/etc/sysctl.d/`.
- `sysctl --system` from procps reads `/etc/sysctl.conf` last, so it can override every drop-in.

The example below uses wildcard assignments for live network interfaces. `systemd-sysctl` supports them. procps-ng supports the same syntax from version 4.0.0 onward. With an older procps release, use `systemd-sysctl` or replace each wildcard with explicit interface names and arrange for new interfaces to receive the same policy.

For network keys, `all` is not a wildcard. Each setting defines its own rules for combining `all`, `default`, and per-interface values. `default` supplies the initial value for interfaces created later.

## Local hardening

### Temporary-file protections

```ini
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
```

`protected_hardlinks` blocks a common class of hard-link attacks. A user who neither owns a file nor has `CAP_FOWNER` may link it only when the source meets additional safety checks, including read and write access. `protected_symlinks` restricts following links created by another user in sticky world-writable directories such as `/tmp`.

Two related controls protect programs that expect to create a new FIFO or regular file but encounter an existing file owned by someone else:

```ini
fs.protected_fifos = 1
fs.protected_regular = 1
```

Both settings also accept `2`, which extends the check to group-writable sticky directories. Some distributions already use `2`. Keep that value if present. Test mode `2` before adopting it because old temporary-file workflows may fail.

If you do not need core dumps from privileged or otherwise tainted processes, use:

```ini
fs.suid_dumpable = 0
```

Zero is the upstream default. Systems using `systemd-coredump` may deliberately set this to `2` and send privileged dumps to a protected handler. Choose a core-dump policy instead of assuming that the larger number is weaker.

### Address-space protections

```ini
kernel.randomize_va_space = 2
vm.legacy_va_layout = 0
```

`randomize_va_space=2` enables the highest ASLR mode exposed by this sysctl, including heap randomization. Executables still need PIE for their main image to move, and an eligible process can request `ADDR_NO_RANDOMIZE` for itself.

`legacy_va_layout=0` selects the modern memory layout by default. Compatibility flags and an unlimited stack can still select the legacy layout on some architectures.

Check `vm.mmap_min_addr` separately:

```bash
sysctl vm.mmap_min_addr
```

If it is below `65536` and you do not run software that needs low mappings, raise it:

```ini
vm.mmap_min_addr = 65536
```

Do not lower a higher distribution value. Processes with `CAP_SYS_RAWIO` in the initial user namespace may bypass the generic kernel check, and an LSM can impose another limit. Wine, DOS emulators, and similar compatibility software may require a lower address.

### Kernel information exposure

```ini
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
```

The first setting requires `CAP_SYSLOG` to read the kernel log buffer. The second hides addresses printed with `%pK`, including from privileged readers. Neither setting prevents every possible kernel information leak, but both remove useful data from many local exploit chains.

These values make low-level diagnostics less convenient. Access to logs through journald is governed separately.

### Process and kernel interfaces

If Yama is active, `ptrace_scope=1` prevents a process from attaching to any unrelated process owned by the same user:

```ini
kernel.yama.ptrace_scope = 1
```

Normal parent-to-child debugging still works. Attaching `gdb` or `strace` to an existing process as an unprivileged user may not. Keep a current value of `2` or `3`; do not lower it to `1`.

Restrict unprivileged access to kernel attack surfaces where the keys exist:

```ini
net.core.bpf_jit_harden = 2
vm.unprivileged_userfaultfd = 0
dev.tty.ldisc_autoload = 0
dev.tty.legacy_tiocsti = 0
```

`bpf_jit_harden=2` enables BPF JIT hardening for privileged and unprivileged programs. It can cost performance on BPF-heavy systems. `unprivileged_userfaultfd=0` prevents unprivileged callers from handling kernel-mode page faults through the `userfaultfd()` syscall, but it does not restrict `/dev/userfaultfd`; normal device permissions control that path.

`ldisc_autoload=0` stops an unprivileged request from loading a missing TTY line-discipline module. It does not block a line discipline that is already registered. `legacy_tiocsti=0` rejects legacy terminal input injection from unprivileged callers.

Two more controls need a value check before they go into the file:

```bash
sysctl kernel.unprivileged_bpf_disabled
sysctl kernel.perf_event_paranoid
```

If `kernel.unprivileged_bpf_disabled` is `0`, set it to `2`:

```ini
kernel.unprivileged_bpf_disabled = 2
```

Mode `2` blocks unprivileged BPF map and program creation while allowing an administrator to restore mode `0`. It does not disable seccomp-BPF, classic socket filters, or every operation on an existing BPF object. If the current value is `1`, leave it alone. Mode `1` cannot be relaxed until reboot.

For upstream kernels, this is a reasonable minimum:

```ini
kernel.perf_event_paranoid = 2
```

At `2`, unprivileged perf users are limited to per-process user-space monitoring. Raw and ftrace tracepoints are already restricted at `0`; CPU-wide monitoring is restricted at `1`; kernel profiling is restricted at `2`.

Upstream accepts values above `2`, but they behave like `2`. Some distributions give `3` or `4` stricter meanings. Keep those values and follow the distribution's documentation.

## Network hardening for a non-routing host

This section assumes the server does not forward packets. It deliberately leaves `rp_filter` and IPv6 router-advertisement policy for the next section.

### IPv4

Set forwarding first because writing `net.ipv4.ip_forward` resets several IPv4 settings to their host or router defaults:

```ini
net.ipv4.ip_forward = 0
net.ipv4.conf.default.forwarding = 0

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.*.accept_redirects = 0

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.*.send_redirects = 0

net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
```

`ip_forward=0` breaks routing, NAT, and container or VM networks that depend on forwarding. `accept_source_route=0` rejects IPv4 source routing. On a host, redirect acceptance uses `all OR interface`, so the wildcard is needed for live interfaces. Redirect sending also needs both the global and per-interface values cleared.

`icmp_echo_ignore_broadcasts=1` ignores broadcast and multicast ICMP Echo and Timestamp requests. `tcp_syncookies=1` enables SYN cookies when the listen backlog overflows. Both are upstream defaults on current kernels, but listing them pins the intended policy.

`tcp_rfc1337=1` keeps an in-window RST from destroying a TIME-WAIT socket. This follows RFC 1337 and makes TIME-WAIT assassination harder.

Do not set `net.ipv4.icmp_echo_ignore_all=1`. It does not hide a server that exposes other traffic, and it removes a useful diagnostic tool. Do not disable TCP SACK, timestamps, or window scaling to work around old vulnerabilities. Patch the kernel instead.

### IPv6

```ini
net.ipv6.conf.all.forwarding = 0

net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.*.accept_redirects = 0

net.ipv6.conf.all.accept_source_route = -1

net.ipv6.conf.default.suppress_frag_ndisc = 1
net.ipv6.conf.*.suppress_frag_ndisc = 1
```

Writing `all.forwarding=0` updates the live interfaces and the default for future interfaces. As with IPv4, do not use it on a host that needs to forward packets.

IPv6 `accept_redirects` does not propagate from `all`, so the default and wildcard assignments are required. For `accept_source_route`, the kernel uses the minimum of `all` and the interface value. Setting `all=-1` disables Mobile IPv6 Routing Header type 2 processing regardless of the interface value. Routing headers with no segments left may still pass, and Segment Routing or RPL behavior has separate controls.

`suppress_frag_ndisc=1` rejects fragmented Neighbor Discovery packets as described by RFC 6980. It is the current upstream default. The packet check uses the interface value, which is why the example sets both future and live interfaces.

## Settings that depend on the network

### Reverse-path filtering

`rp_filter` is an IPv4 source-validation check. There is no IPv6 equivalent.

- `0` disables the check.
- `1` requires the incoming interface to be the best reverse path to the source.
- `2` accepts the packet if the source is reachable through any interface.

The effective value is the numeric maximum of `all` and the interface. A simple host with one uplink and symmetric routing can use strict mode:

```ini
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.*.rp_filter = 1
```

Strict mode can break multihoming, policy routing, VRFs, VPNs, transparent proxies, and container networking. On those systems, keep `all=0` so each interface can have its own policy. Loose mode is a common starting point:

```ini
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.*.rp_filter = 2
```

Complex routing may need `0` plus explicit firewall or routing-policy checks.

### IPv6 router advertisements

Do not disable router advertisements just because the address comes from DHCPv6. DHCPv6 normally does not provide a default gateway.

For an ordinary host using SLAAC and RA-provided routes:

```ini
net.ipv6.conf.default.accept_ra = 1
net.ipv6.conf.*.accept_ra = 1
net.ipv6.conf.default.autoconf = 1
net.ipv6.conf.*.autoconf = 1
```

If RA supplies routes and MTU information but addresses are configured another way, use `accept_ra=1` and `autoconf=0`. Set both to `0` only when addresses, routes, gateway, and MTU are all managed explicitly.

`accept_ra=2` allows a forwarding interface to keep accepting advertisements. That belongs in a router-specific policy, not this baseline.

## Optional restrictions

These controls reduce attack surface at a real compatibility cost. Test them one at a time.

| Setting | Effect | Common breakage |
| --- | --- | --- |
| `kernel.yama.ptrace_scope = 2` | Only a process with `CAP_SYS_PTRACE` may attach. | Unprivileged debuggers and some crash handlers. |
| `kernel.io_uring_disabled = 1` | New `io_uring_setup()` calls require `CAP_SYS_ADMIN` or membership in `kernel.io_uring_group`. | Newer services and container tools that use io_uring. |
| `kernel.io_uring_disabled = 2` | Denies all new `io_uring_setup()` calls. Existing rings keep working. | Same as mode `1`, including privileged callers after restart. |
| `vm.memfd_noexec = 2` | Requires new memfds to use `MFD_NOEXEC_SEAL`; executable memfds are rejected. | Software that loads executable code from memfd. |
| `user.max_user_namespaces = 0` | Prevents creation of additional user namespaces. | Rootless containers, bubblewrap, Flatpak, and many application sandboxes. |
| `kernel.sysrq = 0` | Disables keyboard and serial-console SysRq. | Emergency local recovery. Privileged writes to `/proc/sysrq-trigger` still work. |

`kernel.io_uring_group` defaults to `-1`, meaning no group exception. Set it to a trusted group's numeric GID only if mode `1` is in use and that group needs io_uring. Existing rings are unaffected by either disable mode, so restart affected programs when testing.

`vm.memfd_noexec=1` is a migration mode. It makes flagless `memfd_create()` calls default to non-executable memory, but a caller can still request `MFD_EXEC`. Mode `2` enforces the restriction. The setting is inherited through PID namespaces, and the most restrictive ancestor policy applies.

`user.max_user_namespaces=0` does not remove namespaces that already exist. Some distributions also provide `kernel.unprivileged_userns_clone`; that is a downstream patch, not an upstream sysctl.

## Restrictions that last until reboot

Do not put these in the baseline. Once enabled, they cannot be relaxed without rebooting.

| Setting | Effect | Common breakage |
| --- | --- | --- |
| `kernel.unprivileged_bpf_disabled = 1` | Blocks unprivileged BPF creation and locks the policy. | Any later need to restore unprivileged BPF. |
| `kernel.yama.ptrace_scope = 3` | Disables ptrace attachment for everyone and locks the policy. | Debugging, crash handlers, and some security tools. |
| `kernel.modules_disabled = 1` | Blocks module loading and unloading. | Hotplug, livepatch modules, late filesystem or driver loads, and recovery. |
| `kernel.kexec_load_disabled = 1` | Blocks loading new kexec and crash kernels. | kexec and kdump setup. An image loaded beforehand can still run. |

Preload every required module before setting `modules_disabled=1`. For kdump, check whether the crash image is loaded before or after sysctl configuration on your distribution.

## Example configuration

This example uses systemd-style interface wildcards. It leaves out values that must be compared with the current system first: `fs.protected_fifos`, `fs.protected_regular`, `fs.suid_dumpable`, `vm.mmap_min_addr`, `kernel.yama.ptrace_scope`, `kernel.unprivileged_bpf_disabled`, and `kernel.perf_event_paranoid`.

Add those settings only after reading the relevant sections above. Remove any other key your kernel does not expose.

```ini
# /etc/sysctl.d/90-server-hardening.conf

# Local hardening
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
kernel.randomize_va_space = 2
vm.legacy_va_layout = 0
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
net.core.bpf_jit_harden = 2
vm.unprivileged_userfaultfd = 0
dev.tty.ldisc_autoload = 0
dev.tty.legacy_tiocsti = 0

# IPv4 endpoint. Keep forwarding first.
net.ipv4.ip_forward = 0
net.ipv4.conf.default.forwarding = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.*.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.*.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1

# IPv6 endpoint
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.*.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = -1
net.ipv6.conf.default.suppress_frag_ndisc = 1
net.ipv6.conf.*.suppress_frag_ndisc = 1
```

The wildcard patterns also match `all` and `default` by name. An explicit assignment excludes that key from matching systemd wildcards, regardless of line order. Keeping each `default` assignment before its wildcard still ensures that an interface created while the file is being processed inherits the intended value.

## Apply and verify the configuration

1. Save a read-only snapshot for reference. Do not load this entire file later; `sysctl -a` also contains read-only and unrelated keys.

    ```bash
    sudo sysctl -a | sudo tee /root/sysctl-hardening.before.txt >/dev/null
    ```

1. Create `/etc/sysctl.d/90-server-hardening.conf` from the example and any conditional additions you chose.

1. On a systemd host, apply the same loader used at boot and inspect its log:

    ```bash
    sudo systemctl restart systemd-sysctl.service
    sudo journalctl -b -u systemd-sysctl.service --no-pager
    ```

1. On a system that intentionally uses procps, test the file directly. Wildcards require procps-ng 4.0.0 or newer.

    ```bash
    sysctl --version
    sudo sysctl -p /etc/sysctl.d/90-server-hardening.conf
    sudo sysctl --system
    ```

    The second command loads only this file. The third loads the full procps configuration, including `/etc/sysctl.conf` last. Values may change between the two commands if another file overrides them.

1. Read the effective local settings back:

    ```bash
    sudo sysctl -a --pattern '^(fs\.(protected_(hardlinks|symlinks|fifos|regular)|suid_dumpable)|kernel\.(randomize_va_space|dmesg_restrict|kptr_restrict|yama\.ptrace_scope|unprivileged_bpf_disabled|perf_event_paranoid)|vm\.(legacy_va_layout|mmap_min_addr|unprivileged_userfaultfd)|net\.core\.bpf_jit_harden|dev\.tty\.(ldisc_autoload|legacy_tiocsti)|net\.ipv4\.(ip_forward|icmp_echo_ignore_broadcasts|tcp_syncookies|tcp_rfc1337))$'
    ```

1. Read every matching interface setting back:

    ```bash
    sudo sysctl -a --pattern '^net\.ipv(4|6)\.conf\..+\.(forwarding|accept_redirects|accept_source_route|send_redirects|suppress_frag_ndisc|rp_filter|accept_ra|autoconf)$'
    ```

1. Reboot once and repeat both checks. This confirms that the settings survive boot and that no later service changes them.

Do not hide unknown-key errors. Remove unsupported keys or work out why a module-dependent setting was unavailable when the loader ran.

## Roll back

Moving the file out of the way prevents it from loading at the next boot:

```bash
sudo mv /etc/sysctl.d/90-server-hardening.conf \
  /etc/sysctl.d/90-server-hardening.conf.disabled
```

Removing the file does not restore runtime values. For an immediate rollback, use the snapshot to find each previous value and write it back explicitly:

```bash
sudo sysctl -w kernel.dmesg_restrict=PREVIOUS_VALUE
```

Otherwise, reboot after moving the file. The remaining distribution and administrator configuration will then apply normally. Values described as locked until reboot cannot be restored in the running kernel.

## What changed from the old list

The following keys were removed because they are gone, unused, ineffective, or not persistent settings:

| Old key | Reason |
| --- | --- |
| `kernel.maps_protect` | Never an upstream sysctl. |
| `net.ipv4.tcp_tw_recycle` | Removed in Linux 4.12. |
| `net.ipv4.conf.all.bootp_relay` | Exposed but not implemented. |
| `net.ipv4.neigh.default.gc_interval` | Unused since Linux 2.6.8. |
| `net.ipv4.ipfrag_low_thresh`, `net.ipv6.ip6frag_low_thresh` | Obsolete low-water controls. |
| `net.ipv4.udp_wmem_min` | Has no effect because UDP transmit memory is not accounted this way. |
| `net.ipv4.route.flush`, `net.ipv6.route.flush` | One-shot operations, not persistent policy. |
| Hard-coded `eth0` and `lo` entries | Interface names and network roles are not portable. |

The old file also changed file-handle limits, SysV IPC limits, socket buffers, queue sizes, fragment memory, neighbor tables, congestion control, keepalive, retries, writeback, overcommit, and swapping. Those settings affect capacity or performance and need workload measurements, not a generic security value.

Several old recommendations were actively harmful. `tcp_sack=0` and `tcp_window_scaling=0` damaged TCP performance. `icmp_echo_ignore_all=1` broke monitoring without hiding the server. `dad_transmits=0` disabled IPv6 duplicate-address detection. Blanket `accept_ra=0` removed IPv6 default routes on networks that rely on router advertisements.

## References

- [Kernel sysctl index](https://docs.kernel.org/admin-guide/sysctl/index.html)
- [Filesystem sysctls](https://docs.kernel.org/admin-guide/sysctl/fs.html)
- [Kernel sysctls](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [Virtual-memory sysctls](https://docs.kernel.org/admin-guide/sysctl/vm.html)
- [Network-core sysctls](https://docs.kernel.org/admin-guide/sysctl/net.html)
- [IPv4 and IPv6 sysctls](https://docs.kernel.org/networking/ip-sysctl.html)
- [Yama](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [Perf security](https://docs.kernel.org/admin-guide/perf-security.html)
- [Userfaultfd](https://docs.kernel.org/admin-guide/mm/userfaultfd.html)
- [Non-executable memfd](https://docs.kernel.org/userspace-api/mfd_noexec.html)
- [Kernel self-protection](https://docs.kernel.org/security/self-protection.html)
- [systemd sysctl.d](https://man7.org/linux/man-pages/man5/sysctl.d.5.html)
- [procps sysctl.conf](https://man7.org/linux/man-pages/man5/sysctl.conf.5.html)
- [procps sysctl](https://man7.org/linux/man-pages/man8/sysctl.8.html)
