local DSL = "podman"
local schema = {
	service_ip = "/%s/ip", --> string
	service_ports = "/%s/ports", --> list{string}
}
local dummy_netdev = [[
[NetDev]
Name=__NAME__
Kind=dummy
]]
local dummy_network = [[
[Match]
Name=__NAME__
[Network]
Address=__IP__/32
LinkLocalAddressing=no
IPv6AcceptRA=no
[Link]
MTUBytes=65536
]]
fs.mkdir("/etc/podman.etcdb")
local bitcask = require("bitcask")
local kv_running = bitcask.open("/etc/podman.etcdb/running")
local kv_service = bitcask.open("/etc/podman.etcdb/service")
local lopper = require("lopper")
local json = require("json")
local util = require("util")
local ok = function(msg, tbl)
	tbl._module = DSL
	return lopper.Ok(msg, tbl)
end
local panic = function(ret, msg, tbl)
	if not ret then
		tbl._module = DSL
		kv_running:close()
		kv_service:close()
		return lopper.Panic(msg, tbl)
	end
end
local M = {}
local podman = exec.ctx("podman")
local start = function(name, unit, cpus, iid, ip)
	local systemctl = exec.ctx("systemctl")
	systemctl({
		"disable",
		"--no-block",
		"--now",
		("%s.service"):format(name),
	})
	local fname = ("/etc/systemd/system/%s.service"):format(name)
	local changed
	unit, changed = unit:gsub("__ID__", iid)
	panic((changed == 1), "unable to interpolate image ID", {
		what = "string.gsub",
		changed = false,
		to = iid,
	})
	if unit:contains("__IP__") then
		unit, changed = unit:gsub("__IP__", ip)
		panic((changed>=1), "unable to interpolate IP", {
			what = "string.gsub",
			changed = false,
			to = ip,
		})
	end
	unit, changed = unit:gsub("__CPUS__", cpus)
	panic((changed == 1), "unable to interpolate cpuset-cpus", {
		what = "string.gsub",
		changed = false,
		to = cpus,
	})
	panic(fs.write(fname, unit), "unable to write unit", {
		what = "fs.write",
		file = fname,
	})
	local r, so, se = systemctl({
		"enable",
		"--no-block",
		"--now",
		("%s.service"):format(name),
	})
	panic(r, "unable to start service", {
		what = "systemctl",
		command = "enable",
		service = name,
		stdout = so,
		stderr = se,
	})
end
local id = function(u, t)
	local r, so, se = podman({
		"images",
		"--format",
		"json",
	})
	panic(r, "unable to list images", {
		what = "podman",
		command = "images",
		stdout = so,
		stderr = se,
	})
	local j = json.decode(so)
	_, u = util.path_split(u)
	local name = ("%s:%s"):format(u, t)
	for i = 1, #j do
		if table.find(j[i].Names, name) then
			return j[i].Id
		end
	end
	return nil, "Container image not found."
end
local pull = function(u, t)
	local r, so, se = podman({
		"pull",
		"--tls-verify",
		("%s:%s"):format(u, t),
	})
	panic(r, "unable to pull image", {
		what = "podman",
		command = "pull",
		url = u,
		tag = t,
		stdout = so,
		stderr = se,
	})
end
local assign_ip = function(n, ip)
	local netdev = dummy_netdev:gsub("__NAME__", n)
	local network = dummy_network:gsub("__NAME__", n)
	network = network:gsub("__IP__", ip)
	local fnetdev = ("/etc/systemd/network/%s.netdev"):format(n)
	local fnetwork = ("/etc/systemd/network/%s.network"):format(n)
	panic(fs.write(fnetdev, netdev), "unable to write .netdev configuration", {
			what = "dummy network",
			file = fnetdev,
		})
	panic(fs.write(fnetwork, network), "unable to write .network configuration", {
			what = "dummy network",
			file = fnetwork,
		})
	local systemctl = exec.ctx("systemctl")
	systemctl({"restart", "systemd-networkd"})
	local ipargs = {"-j", "addr", "show", "dev", n}
	local ipcmd = util.retry_f(exec.ctx("ip"))
	local ret, so, se = ipcmd(ipargs)
	panic(ret, "failure running ip command", {
		what = "dummy network",
		stdout = so,
		stderr = se,
	})
	local check = json.decode(so)
	panic(table.find(check, n), "ifname did not match", {
		what = "dummy network",
		expected = n,
	})
	panic(table.find(check, ip), "local IP did not match", {
		what = "dummy network",
		expected = ip,
	})
	return ip
end
local volume = function(vt)
	local volumes = function(n)
		local ret, so, se = podman({
			"volume",
			"inspect",
			"--all",
		})
		panic(ret, "Failure listing volumes", {
			what = "podman",
			command = "volume-ls",
			stdout = so,
			stderr = se,
		})
		local j = json.decode(so)
		local found = {}
		for _, v in ipairs(j) do
			if n and v.Name == n then
				return v.Mountpoint
			end
			found[v.Name] = v.Mountpoint
		end
		return found
	end
	local found = volumes()
	for x, y in pairs(vt) do
		if not found[x] then
			local ret, so, se = podman({ "volume", "create", x })
			panic(ret, "unable to create volume", {
				what = "podman",
				command = "volume-create",
				stdout = so,
				stderr = se,
			})
		end
		local mountpoint = volumes(x)
		local sh = exec.ctx("sh")
		if type(y) == "table" then
			for _, cmd in ipairs(y) do
				local ret, so, se = sh({ "-c", cmd:gsub("__MOUNTPOINT__", mountpoint) })
				panic(ret, "error executing volume command", {
					what = "sh",
					command = "volume-command",
					stdout = so,
					stderr = se,
				})
			end
		end
	end
end
setmetatable(M, {
	__call = function(_, p)
		local param = {
			NAME = "Unit name.",
			URL = "Image URL.",
			TAG = "Image tag.",
			CPUS = "Argument to podman --cpuset-cpus.",
			ARGS = "Arguments to any function hooks.",
			IP = "Assigned IP for container",
			always_update = "Boolean flag, if `true` always pull the image.",
		}
		M.param = {}
		M.reg = {}
		for k in pairs(p) do
			if not param[k] then
				panic(nil, "Invalid parameter given.", {
					parameter = k,
				})
			else
				M.param[k] = p[k]
			end
		end

		local systemd = require("systemd." .. M.param.NAME)
		local instance
		M.param.ARGS = M.param.ARGS or {}
		if next(M.param.ARGS) then
			instance = systemd(M.param.ARGS)
		else
			instance = systemd
		end
		if next(instance.volumes) then
			volume(instance.volumes)
			for vn in pairs(instance.volumes) do
				ok("Checked volume", {
					name = vn,
				})
			end
		end
		if instance.ports and next(instance.ports) then
			local kx, ky = kv_service:put(schema.service_ports:format(M.param.NAME), json.encode(instance.ports))
			panic(kx, "unable to add ports to etcdb", {
				error = ky
			})
		end
		M.reg.unit = instance.unit

		-- pull
		M.reg.id = id(M.param.URL, M.param.TAG)
		if M.param.always_update or not M.reg.id then
			pull(M.param.URL, M.param.TAG)
			ok("Pulled image", {
				url = M.param.URL,
				tag = M.param.TAG,
			})
			M.reg.id = id(M.param.URL, M.param.TAG)
			ok("Got image ID", {
				id = M.reg.id,
			})
		end
		if M.param.IP then
			assign_ip(M.param.NAME, M.param.IP)
			local kx, ky = kv_service:put(schema.service_ip:format(M.param.NAME), M.param.IP)
			panic(kx, "unable to add ip to etcdb", {
				error = ky
			})
		end
		-- start
		do
			fs.mkdir("/etc/podman.seccomp")
			local fn = ("/etc/podman.seccomp/%s.json"):format(M.param.NAME)
			local default =  require("systemd.seccomp")
			local seccomp = json.encode(default)
			panic(fs.write(fn, seccomp), "unable to write seccomp profile", {
				filename = fn,
			})
		end
		start(M.param.NAME, M.reg.unit, M.param.CPUS, M.reg.id, M.param.IP)
		do
			local kx, ky = kv_running:put(M.param.NAME, "ok")
			panic(kx, "unable to add service to etcdb", {
				error = ky
			})
		end
		kv_running:close()
		kv_service:close()
		ok("Started systemd unit", {
			name = M.param.NAME,
		})
	end,
})
return M
