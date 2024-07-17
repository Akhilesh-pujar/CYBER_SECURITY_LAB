from scapy.all import traceroute

# Define the target host
target = "www.google.com"

# Perform the traceroute
result, unanswered = traceroute(target, maxttl=30)

# Save the result to a file
result.show()
result.pdfdump("traceroute_results.pdf")

