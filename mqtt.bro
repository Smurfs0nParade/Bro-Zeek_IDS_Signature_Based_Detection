# Looks for a 'subscribe all' for the MQQT protocol

module MQTT;

export {
redef enum Notice::Type +=
	{
		Mqtt::Subscribe,
	};
}

# Tests all TCP packets
event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
{
	# Detects the use of MQQT Protocol
	if (c$id$resp_p == 1883/tcp)
	{
		local packetPayload = string_to_ascii_hex(payload);
		local length = 0;
		local content = "";
		local subscribeCount = 0;
		local topic = "";
		
		# Iterates through packet payload looking for a subscribe and then a subscribe all
		while (payload != "")
		{
			length = bytestring_to_count(payload[1:2]);
			length = length + 2;
			content = payload[0:length];
			payload = subst_string(payload, content, "");
			
			if (content[0:1] == "\x82")
			{
				topic = content[length - 2:length-1];
					if (topic == "#")
					{
						NOTICE([$note=Mqtt::Subscribe, $msg=fmt(rstrip(addr_to_ptr_name(c$id$orig_h), ".in-addr.arpa") + " attempts to subscribe to " + topic + " topics.")]);
						print "Alert Raised!";
					}
			}
	}
}

