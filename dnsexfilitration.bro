export 
{
	redef enum Notice::Type += { DNS::Exfiltration };
	redef ignore_checksums = T;
}

event dns_request(c:connection, msg: dns_msg, query: string, qtype: count, qclass: count) 
{
	if (|query| > 52) 
	{
		NOTICE([ $note = DNS::Exfiltration, $msg = fmt("Long Domain. Possible DNS exfiltration/tunnel by %s. Offending domain name: %s", c$id$orig_h, query)]);
	}
}