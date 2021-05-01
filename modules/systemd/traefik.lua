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
		rawset(t, "capabilities", { "net_bind_service" })
		rawset(t, "mounts", {
			["traefik-config"] = "/config",
			["traefik-logs"] = "/logs",
		})
		return t
	end
})
