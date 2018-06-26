-- suriwire
-- A wireshark plugin to integrate suricata alerts and logs in wireshark
-- pcap output.
--
-- (c) 2011,2014 Eric Leblond <eric@regit.org>
--
-- Version 0.2.
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
	local suri_gid = ProtoField.string("suricata.alert.gid", "GID", FT_INTEGER)
	local suri_sid = ProtoField.string("suricata.alert.sid", "SID", FT_INTEGER)
	local suri_rev = ProtoField.string("suricata.alert.rev", "Rev", FT_INTEGER)
	local suri_msg = ProtoField.string("suricata.alert.msg", "Message", FT_STRING)
	local suri_tls_subject = ProtoField.string("suricata.tls.subject", "TLS subject", FT_STRING)
	local suri_tls_issuerdn = ProtoField.string("suricata.tls.issuerdn", "TLS issuer DN", FT_STRING)
	local suri_tls_fingerprint = ProtoField.string("suricata.tls.fingerprint", "TLS fingerprint", FT_STRING)
	local suri_tls_version = ProtoField.string("suricata.tls.version", "TLS version", FT_STRING)

	local suri_ssh_client_version = ProtoField.string("suricata.ssh.client.version", "SSH client version", FT_STRING)
	local suri_ssh_client_proto = ProtoField.string("suricata.ssh.client.proto", "SSH client protocol", FT_STRING)
	local suri_ssh_server_version = ProtoField.string("suricata.ssh.server.version", "SSH server version", FT_STRING)
	local suri_ssh_server_proto = ProtoField.string("suricata.ssh.server.proto", "SSH server protocol", FT_STRING)

	local suri_fileinfo_filename = ProtoField.string("suricata.fileinfo.filename", "Fileinfo filename", FT_STRING)
	local suri_fileinfo_magic = ProtoField.string("suricata.fileinfo.magic", "Fileinfo magic", FT_STRING)
	local suri_fileinfo_md5 = ProtoField.string("suricata.fileinfo.md5", "Fileinfo md5", FT_STRING)
	local suri_fileinfo_sha1 = ProtoField.string("suricata.fileinfo.sha1", "Fileinfo sha1", FT_STRING)
	local suri_fileinfo_sha256 = ProtoField.string("suricata.fileinfo.sha256", "Fileinfo sha256", FT_STRING)
	local suri_fileinfo_size = ProtoField.string("suricata.fileinfo.size", "Fileinfo size", FT_INTEGER)
	local suri_fileinfo_stored = ProtoField.string("suricata.fileinfo.stored", "Fileinfo stored", FT_STRING)

	local suri_http_url = ProtoField.string("suricata.http.url", "HTTP URL", FT_STRING)
	local suri_http_hostname = ProtoField.string("suricata.http.hostname", "HTTP hostname", FT_STRING)
	local suri_http_user_agent = ProtoField.string("suricata.http.user_agent", "HTTP user agent", FT_STRING)
	local suri_http_content_type = ProtoField.string("suricata.http.content_type", "HTTP Content Type", FT_STRING)
	local suri_http_method = ProtoField.string("suricata.http.method", "HTTP Method", FT_STRING)
	local suri_http_protocol = ProtoField.string("suricata.http.protocol", "HTTP Protocol", FT_STRING)
	local suri_http_status = ProtoField.string("suricata.http.status", "HTTP Status", FT_STRING)
	local suri_http_length = ProtoField.string("suricata.http.length", "HTTP Length", FT_STRING)
	local suri_http_referer = ProtoField.string("suricata.http.referer", "HTTP Referer", FT_STRING)

	local suri_smb_command = ProtoField.string("suricata.smb.command", "SMB Command", FT_STRING)
	local suri_smb_filename = ProtoField.string("suricata.smb.filename", "SMB Filename", FT_STRING)
	local suri_smb_share = ProtoField.string("suricata.smb.share", "SMB Share", FT_STRING)
	local suri_smb_status = ProtoField.string("suricata.smb.status", "SMB Status", FT_STRING)

	local suri_prefs = suri_proto.prefs
	local suri_running = false

	local suri_alerts = {}

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
				suri_ssh_client_version, suri_ssh_client_proto, suri_ssh_server_version, suri_ssh_server_proto,
				suri_fileinfo_filename, suri_fileinfo_magic, suri_fileinfo_md5, suri_fileinfo_sha1, suri_fileinfo_sha256,
				suri_fileinfo_size, suri_fileinfo_stored, 
				suri_http_url, suri_http_hostname, suri_http_user_agent,
				suri_http_content_type, suri_http_method, suri_http_protocol, suri_http_status, suri_http_length, suri_http_referer,
				suri_smb_command, suri_smb_filename, suri_smb_share, suri_smb_status
				}


	function suri_proto.dissector(buffer,pinfo,tree)
		if not(suri_alerts[pinfo.number] == nil) then
			for i, val in ipairs(suri_alerts[pinfo.number]) do
				if val['sid'] then
					subtree = tree:add(suri_proto,
							"Suricata alert: "..val['sid'].." ("..val['msg']..")")
					-- add protocol fields to subtree
					subtree:add(suri_gid, val['gid'])
					subtree:add(suri_sid, val['sid'])
					subtree:add(suri_rev, val['rev'])
					subtree:add(suri_msg, val['msg'])
					subtree:add_expert_info(PI_MALFORMED, PI_WARN, val['msg'])
				elseif val['tls_subject'] then
					subtree = tree:add(suri_proto, "Suricata TLS Info")
					-- add protocol fields to subtree
					subtree:add(suri_tls_subject, val['tls_subject'])
					subtree:add(suri_tls_issuerdn, val['tls_issuerdn'])
					subtree:add(suri_tls_fingerprint, val['tls_fingerprint'])
					subtree:add(suri_tls_version, val['tls_version'])
					subtree:add_expert_info(PI_REASSEMBLE, PI_NOTE, 'TLS Info')
				elseif val['ssh_client_version'] then
					subtree = tree:add(suri_proto, "Suricata SSH Info")
					-- add protocol fields to subtree
					subtree:add(suri_ssh_client_version, val['ssh_client_version'])
					subtree:add(suri_ssh_client_proto, val['ssh_client_proto'])
					subtree:add(suri_ssh_server_version, val['ssh_server_version'])
					subtree:add(suri_ssh_server_proto, val['ssh_server_proto'])
					subtree:add_expert_info(PI_REASSEMBLE, PI_NOTE, 'SSH Info')
				elseif val['fileinfo_filename'] then
					subtree = tree:add(suri_proto, "Suricata File Info")
					-- add protocol fields to subtree
					subtree:add(suri_fileinfo_filename, val['fileinfo_filename'])
					if val['fileinfo_magic'] then
						subtree:add(suri_fileinfo_magic, val['fileinfo_magic'])
					end
					if val['fileinfo_md5'] then
						subtree:add(suri_fileinfo_md5, val['fileinfo_md5'])
					end
					if val['fileinfo_sha1'] then
						subtree:add(suri_fileinfo_sha1, val['fileinfo_sha1'])
					end
					if val['fileinfo_sha256'] then
						subtree:add(suri_fileinfo_sha256, val['fileinfo_sha256'])
					end
					subtree:add(suri_fileinfo_size, val['fileinfo_size'])
					if val['fileinfo_stored'] then
						subtree:add(suri_fileinfo_stored, val['fileinfo_stored'])
					end
				end
				if val['http_url'] then
					subtree = tree:add(suri_proto, "Suricata HTTP Info")
					-- add protocol fields to subtree
					subtree:add(suri_http_url, val['http_url'])
					subtree:add(suri_http_hostname, val['http_hostname'])
					if val['http_user_agent'] then
						subtree:add(suri_http_user_agent, val['http_user_agent'])
					end
					if val['http_content_type'] then
						subtree:add(suri_http_content_type, val['http_content_type'])
					end
					if val['http_method'] then
						subtree:add(suri_http_method, val['http_method'])
					end
					if val['http_protocol'] then
						subtree:add(suri_http_protocol, val['http_protocol'])
					end
					if val['http_status'] then
						subtree:add(suri_http_status, val['http_status'])
					end
					if val['http_length'] then
						subtree:add(suri_http_length, val['http_length'])
					end
					if val['http_referer'] then
						subtree:add(suri_http_referer, val['http_referer'])
					end
				end
				if val['smb_command'] then
					subtree = tree:add(suri_proto, "Suricata SMB Info")
					subtree:add(suri_smb_command, val['smb_command'])
					if val['smb_filename'] then
						subtree:add(suri_smb_filename, val['smb_filename'])
					end
					if val['smb_share'] then
						subtree:add(suri_smb_share, val['smb_share'])
					end
					if val['smb_status'] then
						subtree:add(suri_smb_status, val['smb_status'])
					end
				end
		     end
	     end
	end

	function suri_proto.init()
	end

	-- register our protocol as a postdissector
	function suriwire_activate(eve_file)
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
					elseif event["event_type"] == "fileinfo" then
						if suri_alerts[id] == nil then
							suri_alerts[id] = {}
						end
						table.insert(suri_alerts[id],
							{ fileinfo_filename = event["fileinfo"]["filename"],
							  fileinfo_magic = event["fileinfo"]["magic"],
							  fileinfo_md5 = event["fileinfo"]["md5"],
							  fileinfo_sha1 = event["fileinfo"]["sha1"],
							  fileinfo_sha256 = event["fileinfo"]["sha256"],
							  fileinfo_size = tonumber(event["fileinfo"]["size"]),
							  fileinfo_stored = tostring(event["fileinfo"]["stored"]),
							})
					elseif event["event_type"] == "http" then
						if suri_alerts[id] == nil then
							suri_alerts[id] = {}
						end
						table.insert(suri_alerts[id],
							{
								http_url = event["http"]["url"],
								http_hostname = event["http"]["hostname"],
								http_user_agent = event["http"]["http_user_agent"],
								http_content_type = event["http"]["http_content_type"],
								http_method = event["http"]["http_method"],
								http_protocol = event["http"]["protocol"],
								http_status = event["http"]["status"],
								http_length = event["http"]["length"],
								http_referer = event["http"]["http_refer"]
							})
					elseif event["event_type"] == "smb" then
						if suri_alerts[id] == nil then
							suri_alerts[id] = {}
						end
						table.insert(suri_alerts[id],
							{
								smb_command = event["smb"]["command"],
								smb_filename = event["smb"]["filename"],
								smb_share = event["smb"]["share"],
								smb_status = event["smb"]["status"],
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
		if eve_file then
			suriwire_register(eve_file)
		else
			new_dialog("Choose alert file",
			           suriwire_register,
			           "Choose file (default:" .. suri_prefs.alert_file..")")
		end
	end

	function suriwire_page()
		browser_open_url("http://home.regit.org/software/suriwire")
	end

	register_menu("Suricata/Activate", suriwire_activate, MENU_TOOLS_UNSORTED)
	-- register_menu("Suricata/Run Suricata", suriwire_run, MENU_TOOLS_UNSORTED)
	register_menu("Suricata/Web", suriwire_page, MENU_TOOLS_UNSORTED)
	-- activate on startup if SURIWIRE_EVE_FILE env variable is set
	local eve_file = os.getenv("SURIWIRE_EVE_FILE")
	if eve_file then
		suriwire_activate(eve_file)
	end
end
