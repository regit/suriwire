suri_alerts = {}
suri_proto = Proto("suricata","Suricata Postdissector")
-- create a function to "postdissect" each frame
local suri_sid = ProtoField.string("myproto.sid", "SID", FT_STRING)
local suri_msg = ProtoField.string("myproto.msg", "Message", FT_STRING)

function suri_proto.dissector(buffer,pinfo,tree)
     for i, alert in ipairs(suri_alerts) do
	  a = pinfo.number - alert[1]
          if (pinfo.number - alert[1] == 0) then
             -- print(alert[1])
             subtree = tree:add(suri_proto, buffer[0])
             -- add protocol fields to subtree
             subtree:add(suri_msg, "SID: " .. alert[2] .. ": "):append_text(alert[3])
	     subtree:add_expert_info(PI_MALFORMED, PI_WARN, alert[3])
             break
	  end
     end
end

function suri_proto.init()
    local pat = "(%d+):(%d+):(.*)"
    io.input("sample.log")
    -- read the lines in table 'lines'
    for line in io.lines() do
      local alert = {}
      for id, sid, text in string.gmatch(line, pat) do
          table.insert(alert, id)
          table.insert(alert, sid)
          table.insert(alert, text)
      end
      table.insert(suri_alerts, alert)
    end
end

-- register our protocol as a postdissector
register_postdissector(suri_proto)
