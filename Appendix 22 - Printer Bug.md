# Forcing authentication with the Printer Bug

This is a feature of MS-RPRN which allows any user to force any machine that is running the Spooler service to connect to another other machine of the user's choice.
An attacker can use this to force a DC to connect to a server that they have already compromised in order to steal the kerberos ticket.
This machine account can then be used in further attacks (e.g. DCSync/Silver Ticket)