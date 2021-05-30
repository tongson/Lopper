podman = require("podman")
pod = {
	NAME = "ll",
	URL = "pod",
	TAG = "latest",
	BASE = "pod",
	NETWORK = { address = "dhcp", interface = "enp3s0" },
	CPUS = "1",
	SHARES = "512",
	MEM = "256m",
}
ll = podman.config(pod)
ll:start()
mariadb = {
	NAME = "mariadb",
	BASE = "mysql",
	URL = "docker://docker.io/library/mariadb",
	TAG = "10.5",
	NETWORK = "ll",
	ENVIRONMENT = {
		MALLOC_ARENA_MAX = "2",
		MYSQL_ROOT_PASSWORD = "irbj0O3Bn1j8Ezja21NdfcMzj7ZFd2lz", 
	},
	CPUS = "3",
	MEM = "1g",
}
database = podman.config(mariadb)
database:start()
redis = {
	NAME = "redis",
	BASE = "redis",
	URL = "docker://docker.io/library/redis",
	TAG = "6.2-alpine",
	NETWORK = "ll",
	CPUS = "3",
	MEM = "256m",
}
kv = podman.config(redis)
kv:start()
test = {
	NAME = "devel",
	URL = "ll",
	TAG = "latest",
	NETWORK = "ll",
	CPUS = "3",
	MEM = "2g",
}
devel = podman.config(test)
devel:start()
