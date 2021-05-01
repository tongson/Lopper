#!/usr/bin/env lopper
T = require("test")

Notify("start Lopper tests...")
sh = Command("sh")
sh.cwd = "/tmp"
sh("-c", "touch CMD")
T["CMD"] = function()
	T.is_true(fs.isfile("/tmp/CMD"))
	os.remove("/tmp/CMD")
end

Shell.CWD = "/tmp"
Shell([[
set -efu
touch "/tmp/SH"
]])
T["SH"] = function()
	T.is_true(fs.isfile("/tmp/SH"))
	os.remove("/tmp/SH")
end

script = [[
set -efu
touch "/tmp/${VAR:-SCRIPT_OK}"
]]
fs.write("/tmp/script.sh", script)
Script.ENV = { "VAR=SCRIPT" }
Script("/tmp/script.sh")
T["SCRIPT #1"] = function()
	T.is_true(fs.isfile("/tmp/SCRIPT"))
	os.remove("/tmp/SCRIPT")
end
Script("/tmp/script.sh")
T["SCRIPT #2"] = function()
	T.is_true(fs.isfile("/tmp/SCRIPT_OK"))
	os.remove("/tmp/SCRIPT_OK")
end
script = [[
set -efu
echo "${NIL}"
]]
fs.write("/tmp/script.sh", script)
Script.IGNORE = true
Script("/tmp/script.sh")
T["SCRIPT #3"] = function()
	T.is_string("SHOULD EXECUTE THIS TEST")
end

text = "%s" % "one"
T["interpolation #1"] = function()
	T.equal(text, "one")
end

text = "%s:%s" %  { "one", "two" }
T["interpolation #2"] = function()
	T.equal(text, "one:two")
end

dummy = require("lopper_dummy")
T["environment does not cross"] = function()
	T.is_function(dummy.test())
end

dummy = require("lopper_dummy")
T["string metatable is global"] = function()
	T.equal(dummy.interpolation(), "yes")
end
Notify("end Lopper tests")

T.summary()
