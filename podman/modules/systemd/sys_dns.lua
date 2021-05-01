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
	mounts = {
		["sys_dns-config"] = "/config",
	},
	capabilities = { "net_bind_service" },
}
