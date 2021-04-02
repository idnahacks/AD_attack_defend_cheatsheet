# AdminSDHolder
## What is it?
This is a domain object that is used to control permissions for Protected Groups using an ACL.

Protected Groups are:
 - Account Operators
 - Backup Operators
 - Server Operators
 - Print Operators
 - Domain Admins
 - Replicator
 - Enterprise Admins
 - Domain Controllers
 - Read-only Domain Controllers
 - Schema Admins
 - Administrators

The SDPROP (Security Descriptor Propagator) runs every hour and compares ACLs of protected groups and their members with the ACL of the AdminSDHolder (the Golden ACL) and overwrites any differences found on the Protected Groups.

## How can it be abused?
If you can add an account under your control to the AdminSDHolder "Golden" ACL and give it full control, that will propagate down to the ACLs of all protected groups.

This can be used for persistence after you obtain Domain Admin privileges.