local crypto = require("crypto")
local json = require("json")
local refmt = require("refmt")
local encode = crypto.base64_encode
return setmetatable({}, {
	__call = function(t, args)
		local jmain = json.encode(args.main)
		local jdynamic = json.encode(args.dynamic)
		local main = encode(refmt.yaml(jmain))
		local dynamic = encode(refmt.yaml(jdynamic))
		rawset(t, "volumes", {
				["traefik-config"] = {
					([[printf "%s" | base64 --decode > __MOUNTPOINT__/traefik.yaml]]):format(main),
					([[printf "%s" | base64 --decode > __MOUNTPOINT__/dynamic.yaml]]):format(dynamic),
				},
				["traefik-logs"] = true,
			})
		rawset(t, "unit", [==[
[Unit]
Description=Traefik Container
Wants=network.target
After=network-online.target

[Service]
Environment=PODMAN_SYSTEMD_UNIT=%n
Restart=on-failure
RestartSec=5
Type=forking
PIDFile=/run/podman-traefik.pid
TimeoutStartSec=infinity
TimeoutStopSec=20
SystemCallArchitectures=native
MemoryDenyWriteExecute=yes
LockPersonality=yes
NoNewPrivileges=yes
RemoveIPC=yes
DevicePolicy=closed
PrivateTmp=yes
PrivateNetwork=false
ProtectKernelModules=yes
ProtectSystem=full
ProtectHome=yes
ProtectKernelLogs=yes
ProtectClock=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
#PrivateDevices=yes
RestrictAddressFamilies=AF_INET
SystemCallFilter=~bpf process_vm_writev process_vm_readv perf_event_open kcmp lookup_dcookie move_pages swapon swapoff userfaultfd unshare
SystemCallFilter=~@cpu-emulation @debug @module @obsolete @keyring @clock @raw-io @clock @swap @reboot
ExecStartPre=-/usr/bin/podman stop -i traefik
ExecStartPre=-/usr/bin/podman rm -i -v -f traefik
ExecStop=/usr/bin/podman stop -t 12 traefik
ExecStopPost=-/usr/bin/podman rm -i -v -f traefik
ExecStart=/usr/bin/podman run --name traefik \
--security-opt seccomp=/etc/podman.seccomp/traefik.json \
--network host \
--replace \
--hostname traefik  \
--cap-drop all \
--cap-add net_bind_service \
--conmon-pidfile=/run/podman-traefik.pid \
-e "TZ=UTC" \
--cpuset-cpus __CPUS__ \
-v traefik-config:/config \
-v traefik-logs:/logs __ID__

[Install]
WantedBy=multi-user.target
]==])
		return t
	end
})
