module MQTT;

export {
redef enum Notice::Type +=
	{
		Mqtt::Subscribe,
	};
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
{
	print payload;
	local message = string_to_ascii_hex(payload);
	print message;
	#local length = bytestring_to_count(hexstr_to_bytestring(sub_bytes(message, 3, 2)));
	#print length;
	#print (length + 2) * 2;
	#local phrase = "This is a test";
	#print sub_bytes(phrase, 1, 4);
	
	if (c$id$resp_p == 1883/tcp)
	{
		# print "MQTT Detected!";
		# print payload;
		
		
		
		local j = string_to_ascii_hex(payload);
		local test = bytestring_to_count(hexstr_to_bytestring(sub_bytes(string_to_ascii_hex(payload), 3, 2)));
		test = (test + 2) * 2;
		# print test;
		# print sub_bytes(j, 1, test);
		
		
		
		# Counts how many timesa subscribe is found in the payload
		local subscribeCount = 0;
		# Flag to determine if we are examining a subscribe in the payload
		# 0 if we are not, 1 if we are
		local subscribeFlag = 0;
		# The hex string containing the subscribe request
		local subscribeString = "";
		for (i in payload)
		{
			# Looks for the begining hex of a subscribe request
			if (i == "\x82")
			{
				#print i;
				subscribeString = "";
				subscribeString += i;
				subscribeFlag += 1;
			}
			subscribeString += i;
			
			#print subscribeString;
			
			# Tests if we are looking at a subsribe request and if we are
			# at the end of it
			if (subscribeString[5:6] == "\00")
			{
				#print subscribeString;
				#print payload;
				if (subscribeFlag == 1)
				{
					subscribeCount += 1;
					subscribeString = "";
					subscribeFlag = 0;
					
					#print subscribeString;
					#print "Subscribe Detected!";
					
					#NOTICE([$note=Mqtt::Subscribe,
					#$msg=fmt(rstrip(addr_to_ptr_name(c$id$orig_h), ".in-addr.arpa") + " attempts to subscribe to all")]);
					#print "Alert Raised!";
					
				}
			}
		}
		#print subscribeCount;
		#print subscribeString;
	}
	# print c;
	#print "--------------------------------------------------------------------------------";
	#if (subscribeCount > 1)
	#{
	#NOTICE([$note=Mqtt::Subscribe,
		#$msg=fmt(rstrip(addr_to_ptr_name(c$id$orig_h), ".in-addr.arpa") + " attempts to subscribe to all")]);
		#print "Alert Raised!";
	#}
}

