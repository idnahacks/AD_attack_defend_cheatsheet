# MSSQL Server Trust Abuse
SQL Servers provide lots of opportunity for lateral movement as domain users are often mapped to database roles.

If windows authentication is enabled, and a domain user has a sysadmin role, if that user is compromised the attacker also has full database access.

## Database Links
If you have enumerated the SQL server and not found any exciting privileges with your user, then don't panic. Database links may help!

Database links are exactly what they sound like. They allow a SQL server to connect to external sources such as other SQL servers or OLE sources.
Linked SQL servers can execute stored procedures, and these work even across forest trusts.

## How can this be abused?
If you trace the database links from server to server, and eventually end up with an interesting set of privileges and the ability to run commands (xp_cmdshell) you essentially have escalated privileges to that user.
The fact that this works across forest security boundaries is also very interesting.

**Don't forget, that command execution shouldn't be the only goal in a red team engagement. If you have access to a database, is there anything juicy in there?**