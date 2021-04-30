return {
  defaultAction = "SCMP_ACT_ALLOW",
  architectures = { "SCMP_ARCH_X86_64", "SCMP_ARCH_X86" },
  syscalls = {
    {
      names = {
        "ioperm",
        "iopl",
        "pciconfig_iobase",
        "pciconfig_read",
        "pciconfig_write",
        "setdomainname",
        "sethostname",
        "vhangup",
        "ptrace",
        "bpf",
	"process_madvise",
        "process_vm_writev",
        "process_vm_readv",
        "perf_event_open",
        "kcmp",
        "lookup_dcookie",
        "swapon",
        "swapoff",
        "userfaultfd",
        "unshare",
        "commit_creds",
        "kexec_file_load",
        "kexec_load",
        "reboot",
        "nfsservctl",
        "quotactl",
        "acct",
        "modify_ldt",
        "subpage_prot",
        "switch_endian",
        "vm86",
        "vm86old",
        "pidfd_getfd",
        "rtas",
        "clock_adjtime",
        "clock_adjtime64",
        "clock_settime",
        "clock_settime64",
        "settimeofday",
        "delete_module",
        "finit_module",
        "init_module",
        "fsconfig",
        "fsmount",
        "fsopen",
        "fspick",
        "mount",
        "move_mount",
        "open_tree",
        "umount",
        "umount2",
	"fanotify_init",
        "_sysctl",
        "afs_syscall",
        "bdflush",
        "break",
        "create_module",
        "ftime",
        "get_kernel_syms",
        "getpmsg",
        "gtty",
        "idle",
        "lock",
        "mpx",
        "prof",
        "profil",
        "putpmsg",
        "query_module",
        "security",
        "sgetmask",
        "ssetmask",
        "stime",
        "stty",
        "sysfs",
        "tuxcall",
        "ulimit",
        "uselib",
        "ustat",
        "vserver",
        "add_key",
        "keyctl",
        "request_key"
      },
     action = "SCMP_ACT_KILL",
    }
  }
}
