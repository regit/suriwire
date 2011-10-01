-- suriwire
-- A wireshark plugin to integrate suricata alerts in wireshark
-- pcap output.
--
-- (c) 2011 Eric Leblond <eric@regit.org>
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


if (gui_enabled()) then 
	local suri_proto = Proto("suricata", "Suricata Analysis")
	local suri_sid = ProtoField.string("suricata.sid", "SID", FT_INTEGER)
	local suri_msg = ProtoField.string("suricata.msg", "Message", FT_STRING)
	local suri_prefs = suri_proto.prefs
	local suri_running = false
	suri_prefs.alert_file = Pref.string("Alert file", "alert-num.log",
					    "Alert file containing information about pcap")
	suri_proto.fields = {suri_sid, suri_msg}
	-- register our protocol as a postdissector
	function suriwire_activate()
		local suri_alerts = {}
		function suri_proto.dissector(buffer,pinfo,tree)
		     if not(suri_alerts[pinfo.number] == nil) then
		             for i, val in ipairs(suri_alerts[pinfo.number]) do
				     subtree = tree:add(suri_proto,
							"SID: "..val['sid'].." ("..val['msg']..")")
				     -- add protocol fields to subtree
				     subtree:add(suri_sid, val['sid'])
				     subtree:add(suri_msg, val['msg'])
				     subtree:add_expert_info(PI_MALFORMED, PI_WARN, val['msg'])
			     end
		     end
		end

		function suri_proto.init()
		end

		function suriwire_parser(file)
			local id = 0
			local s_text = ""
			local pat = "(%d+):(%d+):0:0:([^\n]*)"
			suri_alerts = {}
			for s_text in io.lines(file) do
				i, sid, text = string.match(s_text, pat)
				id = tonumber(i)
				if (i) then
					if suri_alerts[id] == nil then
						suri_alerts[id] = {}
					end
				table.insert(suri_alerts[id], {sid = sid, msg = text})
				end
			end
		end

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
	register_menu("Suricata/Web", suriwire_page, MENU_TOOLS_UNSORTED)
	-- debug 1.7
	-- suriwire_activate()
end
