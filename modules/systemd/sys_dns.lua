local Corefile = [[
.:53 {
       bind 127.255.255.53
       bufsize 1232
       acl {
               allow net 127.0.0.0/8
               block
       }
       hosts /config/hosts {
               ttl 60
               fallthrough
       }
       loadbalance
       forward . /etc/resolv.conf {
               max_concurrent 1024
       }
       prometheus :9153
       errors
       log
}
]]
local crypto = require("crypto")
Corefile = crypto.base64_encode(Corefile)
return {
	volumes = {
		["sys_dns-config"] = {
			([[printf "%s" | base64 --decode > __MOUNTPOINT__/Corefile]]):format(Corefile),
		}
	},
unit = [==[
[Unit]
Description=sys_dns Container
Wants=network.target
After=network-online.target

[Service]
Environment=PODMAN_SYSTEMD_UNIT=%n
Restart=on-failure
RestartSec=5
TimeoutStartSec=infinity
TimeoutStopSec=120
Type=forking
PIDFile=/run/podman-sys_dns.pid
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
ExecStartPre=-/usr/bin/podman stop -i sys_dns
ExecStartPre=-/usr/bin/podman rm -i -v -f sys_dns
ExecStop=/usr/bin/podman stop -t 12 sys_dns
ExecStopPost=-/usr/bin/podman rm -i -v -f sys_dns
ExecStart=/usr/bin/podman run --name sys_dns \
--security-opt seccomp=/etc/podman.seccomp/sys_dns.json \
--replace \
--network host \
--hostname sys_dns  \
--cap-drop all \
--cap-add net_bind_service \
--conmon-pidfile=/run/podman-sys_dns.pid \
-e "TZ=UTC" \
--volume sys_dns-config:/config \
--cpuset-cpus __CPUS__ \
--memory __MEM__ \
__ID__

[Install]
WantedBy=multi-user.target
]==],
}

