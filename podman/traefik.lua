IP = InterfaceAddr("enp3s0")
Notify("START")
args = {
	main = {
		global = {
			checkNewVersion = false,
			sendAnonymousUsage = false,
		},
		log = {
			filePath = "/logs/log",
			format = "json",
			level = "ERROR",
		},
		accessLog = {
			filePath = "/logs/access",
			format = "json",
		},
		providers = {
			file = {
				filename = "/config/dynamic.yaml",
				watch = true,
			},
		},
		entryPoints = {
			mariadb = {
				address = "%s:3306" % IP,
			},
			metrics = {
				address = "%s:8082" % IP,
			},

		},
	},
	dynamic = {
		metrics = {
			prometheus = {
				entryPoint = "metrics",
			},
		},

		tcp = {
			routers = {
				mariadb = {
					entryPoints = {
						"mariadb",
					},
					rule = "HostSNI(`*`)",
					service = "mariadb",
				},
			},
			services = {
				mariadb = {
					LoadBalancer = {
						servers = {
							{
								address = "mariadb:3306"
							},
						},
					}
				},
			},
		},
	},
}
require("podman")({
	NAME = "traefik",
	URL = "traefik",
	TAG = "2.4.8",
	ARGS = args,
	CPUS = "1",
	SHARES = "512",
	MEM = "512m",
	ENVIRONMENT = { "TZ=UTC" },
})
