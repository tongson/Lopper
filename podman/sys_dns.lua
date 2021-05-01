Notify("START")
p=require("podman")
p({
	NAME = "sys_dns",
	URL = "coredns",
	TAG = "1.8.3",
	CPUS = "3",
	MEM = "512m",
})
