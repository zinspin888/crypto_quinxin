import xmlrpc_bf as x

pairs = [("nosuchuser1", "wrongpass1"), ("nosuchuser2", "wrongpass2")]
st, xml = x.post("www.nimr.or.tz", x.build(pairs))
print("status:", st, "len:", len(xml))
print("verdicts (expect all False):", x.verdicts(xml, len(pairs)))
print("faultCode present:", "faultCode" in xml)
print(xml[:300])
