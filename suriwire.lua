-- suriwire
-- A wireshark plugin to integrate suricata alerts in wireshark
-- pcap output.
--
-- (c) 2011 Eric Leblond <eric@regit.org>
--
-- Version 0.1.
--
-- Wireshark - Network traffic analyzer
-- By Gerald Combs <gerald@wireshark.org>
-- Copyright 1998 Gerald Combs
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 3
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

local json = require("cjson")

if (gui_enabled()) then 
	local suri_proto = Proto("suricata", "Suricata Analysis")
	local suri_gid = ProtoField.string("suricata.gid", "GID", FT_INTEGER)
	local suri_sid = ProtoField.string("suricata.sid", "SID", FT_INTEGER)
	local suri_rev = ProtoField.string("suricata.rev", "Rev", FT_INTEGER)
	local suri_msg = ProtoField.string("suricata.msg", "Message", FT_STRING)
	local suri_tls_subject = ProtoField.string("suricata.tls.subject", "TLS subject", FT_STRING)
	local suri_tls_issuerdn = ProtoField.string("suricata.tls.issuerdn", "TLS issuer DN", FT_STRING)
	local suri_tls_fingerprint = ProtoField.string("suricata.tls.fingerprint", "TLS fingerprint", FT_STRING)
	local suri_tls_version = ProtoField.string("suricata.tls.version", "TLS version", FT_STRING)

	local suri_ssh_client_version = ProtoField.string("suricata.ssh.client.version", "SSH client version", FT_STRING)
	local suri_ssh_client_proto = ProtoField.string("suricata.ssh.client.proto", "SSH client protocol", FT_STRING)
	local suri_ssh_server_version = ProtoField.string("suricata.ssh.server.version", "SSH server version", FT_STRING)
	local suri_ssh_server_proto = ProtoField.string("suricata.ssh.server.proto", "SSH server protocol", FT_STRING)
	local suri_prefs = suri_proto.prefs
	local suri_running = false
	-- suri_prefs.suri_command = Pref.string("Suricata binary", "/usr/bin/suricata",
	--				    "Path to suricata binary")
	-- suri_prefs.config_file = Pref.string("Suricata configuration", "/etc/suricata/suricata.yaml",
	--				    "Alert file containing information about pcap")
	suri_prefs.alert_file = Pref.string("EVE file", "/var/log/suricata/eve.json",
					    "EVE file containing information about pcap")
	-- suri_prefs.copy_alert_file = Pref.bool("Make a copy of alert file", true,
	--				       "When running suricata, create a copy of alert"
	--				       .. " file in the directory of the pcap file")
	suri_proto.fields = {suri_gid, suri_sid, suri_rev, suri_msg, suri_tls_subject, suri_tls_issuerdn, suri_tls_fingerprint, suri_tls_version,
				suri_ssh_client_version, suri_ssh_client_proto, suri_ssh_server_version, suri_ssh_server_proto}
	-- register our protocol as a postdissector
	function suriwire_activate()
		local suri_alerts = {}
		function suri_proto.dissector(buffer,pinfo,tree)
			if not(suri_alerts[pinfo.number] == nil) then
				for i, val in ipairs(suri_alerts[pinfo.number]) do
					if val['sid'] then
						subtree = tree:add(suri_proto,
								"SID: "..val['sid'].." ("..val['msg']..")")
						-- add protocol fields to subtree
						subtree:add(suri_gid, val['gid'])
						subtree:add(suri_sid, val['sid'])
						subtree:add(suri_rev, val['rev'])
						subtree:add(suri_msg, val['msg'])
						subtree:add_expert_info(PI_MALFORMED, PI_WARN, val['msg'])
					elseif val['tls_subject'] then
						subtree = tree:add(suri_proto, "TLS Info")
						-- add protocol fields to subtree
						subtree:add(suri_tls_subject, val['tls_subject'])
						subtree:add(suri_tls_issuerdn, val['tls_issuerdn'])
						subtree:add(suri_tls_fingerprint, val['tls_fingerprint'])
						subtree:add(suri_tls_version, val['tls_version'])
						subtree:add_expert_info(PI_REASSEMBLE, PI_NOTE, 'TLS Info')
					elseif val['ssh_client_version'] then
						subtree = tree:add(suri_proto, "SSH Info")
						-- add protocol fields to subtree
						subtree:add(suri_ssh_client_version, val['ssh_client_version'])
						subtree:add(suri_ssh_client_proto, val['ssh_client_proto'])
						subtree:add(suri_ssh_server_version, val['ssh_server_version'])
						subtree:add(suri_ssh_server_proto, val['ssh_server_proto'])
						subtree:add_expert_info(PI_REASSEMBLE, PI_NOTE, 'SSH Info')
				     end
			     end
		     end
		end

		function suri_proto.init()
		end

		function suriwire_parser(file)
			local event
			local id = 0
			local s_text = ""
			suri_alerts = {}
			for s_text in io.lines(file) do
				event = json.decode(s_text)
				id = event["pcap_cnt"]
				if not (id == nil) then
					if event["event_type"] == "alert" then
						if suri_alerts[id] == nil then
							suri_alerts[id] = {}
						end
						table.insert(suri_alerts[id],
							{gid = tonumber(event["alert"]["gid"]), sid = tonumber(event["alert"]["signature_id"]),
							rev = tonumber(event["alert"]["rev"]), msg = event["alert"]["signature"]})
					elseif event["event_type"] == "tls" then
						if suri_alerts[id] == nil then
							suri_alerts[id] = {}
						end
						table.insert(suri_alerts[id],
							{ tls_subject = event["tls"]["subject"], tls_issuerdn = event["tls"]["issuerdn"],
							tls_fingerprint = event["tls"]["fingerprint"], tls_version = event["tls"]["version"]})
					elseif event["event_type"] == "ssh" then
						if suri_alerts[id] == nil then
							suri_alerts[id] = {}
						end
						table.insert(suri_alerts[id],
							{ ssh_client_version = event["ssh"]["client"]["software_version"],
							ssh_client_proto = event["ssh"]["client"]["proto_version"],
							ssh_server_version = event["ssh"]["server"]["software_version"],
							ssh_server_proto = event["ssh"]["server"]["proto_version"],
							})
					end
				end
			end
		end

		-- function suriwire_run()
		-- 	local file = "myfile.pcap"
		-- 	local suri_command = suri_prefs.suri_command .. " -c " ..
		-- 			     suri_prefs.config_file .. " -r " ..
		-- 			     file
		-- 	-- TODO Progress dialog
		-- 	suri_return, suri_status = os.execute(suri_command)
		-- 	-- if command is run succesfully we will have a log file
		-- 	if suri_status == 1 then
		-- 		-- TODO Text window with output
		-- 		print("Unable to run command:" .. suri_return)
		-- 	else
		-- 		if suri_prefs.copy_alert_file then
		-- 			suri_return, suri_status =
		-- 				os.execute("cp " .. suri_prefs.alert_file .. " " .. file .. ".log")
		-- 			if suri_status == 1 then
		-- 				-- TODO Text window with output
		-- 				print("Unable to copy alert file:" .. suri_return)
		-- 				return
		-- 			end
		-- 		end
		-- 		suriwire_parser(file .. ".log")
		-- 		reload()
		-- 	end
		-- end

		function suriwire_register(file)
			if file == "" then
				file = suri_prefs.alert_file
			end
			local filehandle = io.open(file, "r")

			if not (filehandle == nil) then
				filehandle:close()
				-- parse suricata log file
				suriwire_parser(file)
				-- register protocol dissector
				if suri_running == false then
					register_postdissector(suri_proto)
					suri_running = true
				end
				reload()
			else
				new_dialog("Unable to open '" .. file
					   .. "'. Choose another alert file",
					   suriwire_register,
					   "Choose file (default:" .. suri_prefs.alert_file..")")
			end
		end
		-- run suricata
		-- set input file
		new_dialog("Choose alert file",
			   suriwire_register,
			   "Choose file (default:" .. suri_prefs.alert_file..")")
		-- debug 1.7 
		-- suriwire_register("sample.log")
	end

	function suriwire_page()
		browser_open_url("http://home.regit.org/software/suriwire")
	end

	register_menu("Suricata/Activate", suriwire_activate, MENU_TOOLS_UNSORTED)
	-- register_menu("Suricata/Run Suricata", suriwire_run, MENU_TOOLS_UNSORTED)
	register_menu("Suricata/Web", suriwire_page, MENU_TOOLS_UNSORTED)
	-- debug 1.7
	-- suriwire_activate()
end
