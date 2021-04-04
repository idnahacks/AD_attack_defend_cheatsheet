# AS-REPRoasting
## What is it?
If a user has the attibute "Do not require Kerberos preauthentication" enabled it is possible to perform the same attack as you would with Kerberoasting, except you are able to capture the TGT from the initial authentication request reply (AS-REP) and brute force this offline to give you the account's password.

## Why would you do this?
As no pre-authentication is required this means that you could request this TGT with no initial domain user privileges.

## Targeted AS-REPRoasting
Another scenario is that if you have enough permissions (GenericWrite or GenericAll) for a user, you can forcibly set this attribute and then attack it. If the account password is crackable this would then give you the plain text password for that account.