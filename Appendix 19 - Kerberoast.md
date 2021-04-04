# Kerberoast
## What is it?
Kerberoasting is a super common attack where an authenticated attacker requests a TGS for a Kerberos enabled service (Service Principal Name / SPN) and then brute forces this to retrieve the plaintext password for that account.

## How does it work?
A user with domain credentials can successfully request a TGT from the KDC as they have valid credentials for the account they are using.
Using this TGT they can then request a TGS for an account with an SPN from the KDC which would allow them to use this Kerberos enabled service.

Kerberoasting works by saving the TGS that is received from the KDC instead of using it to authenticate against the target service. As it is encrypted using the password hash of the kerberos enabled service account (the one with the SPN).
an attacker can extract the NTLM hash of this account and brute force it offline.

## Using this attack
This is only really useful against user accounts. This is because machine accounts are very long with a complex character set, which would make brute forcing impossible (or just very difficult and impractical). For this reason, this attack is best focussed on users that have SPNs set as these are more likely to have breakable passwords.

## Targeted Kerberoasting
Another scenario is that if you have enough permissions (GenericWrite or GenericAll) for a user, you can forcibly set as SPN and then attack it. If the account password is crackable this would then give you the plain text password for that account.