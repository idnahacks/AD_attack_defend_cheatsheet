# Kerberos Delegation
## Unconstrained Delegation
### What is it?
Kerberos Delegation allows a server to authenticate with another server as a different user. i.e. a service is impersonating a user.

e.g. A user logs into a web server, the web server then queries the database server as that user so that only information available to that user is displayed.

### How does it work?
 - A user authenticates with the DC
 - The DC replies with a TGT
 - The user then requests a TGS for a service (e.g. a web server) from the DC
 - The DC sees that the service is configured for unconstrained delegation and responds with the TGS **and** the user's TGT
 - The user presents the TGT and the TGS to the service (web server)
 - The service sends the user's TGT to the DC and requests a TGS for the (DB) service
 - The DC responds to the (web) service with the TGS and the (web) server then presents this to the other (DB) service.

### How can it be abused?
If you have a user's TGT you can authenticate as them. In the example above, the web server stores all of the user TGTs that are authenticated with it's web service in the LSASS process.

With Unconstrained Delegation these TGTs are portable, meaning you can reuse them to authenticate against any other server in the domain.

If you can compromise the server and get access to LSASS you can get the TGT of any user that is authenticated to the server. This presents an opportunity for privilege escalation if one of your target users authenticates against that service.

### Targeted Delegation
As with the other Kerberos attacks, if your user has GenericWrite or GenericAll over the target account you can set the Unconstrained Delegation flag.

### Forcing authentication with the Printer Bug
If you have compromised a server that has unconstrained delegation enabled you can either wait for a high privileged account to authenticate against the server, or you can force it with the Printer Bug.
This is a feature of MS-RPRN which allows any user to force any machine that is running the Spooler service to connect to another other machine of the user's choice.
An attacker can use this to force a DC to connect to a server that they have already compromised in order to steal the kerberos ticket.

## Constrained Delegation
### What is it?
When Constrained Delegation is enabled on an account it allows delegated access to specified services on specified computers.

### How it works
If a user logs into a non-Kerberos authenticed service (e.g. a website), the service running this website might require to authenticate internally against a server as the user.
If the service (e.g. webservice) has the AD attribute 'Trusted_To_Authenticate_For_Delegation' and the user's account does not have delegation disabled, the KDC will provide a forwardable ticket to the service in order for it to authenticate as that user (known as a S4U2Self). **The initial service does not need to provide the user's password.**

Once the service has this forwardable ticket it passes it back to the KDC and requests a ticket for the destination service (e.g. CIFS). If the requested SPN is set in the msDS-AllowedToDelegateTo field for the requesting service the KDC will provide a ticket for the destination service (S4U2Proxy).

The webserver will now be able to authenticate against the CIFS service on the other server.

### How can it be abused?
If you can compromise a server that has constrained delegation enabled, you can access the services listed in the msDS-AllowedToDelegateTo field as **any** user.

You can also abuse the face that no service name validation occurs on the target SPN used by the same service account. So if a machine account has delegation enabled you can request a TGS for other services that would be running using the same service account

e.g. if the machine account has the flag msds-allowedtodelegate to set for the service TIME/domaincontroller.domain.com you can abuse this and request a TGS for LDAP/domaincontroller.domain.com as this will be running as the same service account.

LDAP could give you DCSync
HTTP could give you PSRemoting
HOST & RPCSS could give you WMI