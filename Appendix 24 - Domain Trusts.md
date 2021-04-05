# Domain Trusts

Domains in the same forest have an implicit two-way trust. This trust comes via a trust key.

### Domain Trust Tickets
#### How does it work?
Let's take the example of 2 domains in a forest, and a user authenticates against one domain for a target service in the other.
 - The user requests a TGT from the DC in their domain
 - The DC responds with the TGT
 - The user then requests a TGS from the same DC
 - The DC sees that the SPN for the requested service is in a different domain and responds with an inter-realm TGT - which is signed and encrypted with the hash of the Trust Key
 - The user then requests a TGS from the other domain's DC using the inter-realm TGT
 - The other domain DC responds with the TGS for the target service
 - The user accesses the service using the TGS

 #### How can this be abused?
 If you can compromise the domain trust key from your own domain, and present this to the target domain via a forged inter-realm TGT telling the target domain that you are the Enterprise Admin using the SID History attribute, you can elevate privileges. Giving you an inter-realm silver ticket.
 
 SIDHistory is an attribute that is used to let one domain know of the permissions a user has on another trusted domain.
 
 ### krbtgt hash
 Using the domain trust key, you can inject the SID History as part of a regular Mimikatz golden ticket attack, giving you complete access to the parent domain.
 
 ### Trust Flow across forest
 As a Forest Trust is classed as a security boundary (as opposed to a domain trust), if you try to perform the above SID History injection across a Forest or External trust for a high privilege account, SID Filtering will filter this out as a security measure.
 
 However, you can still inject the domain trust key into a TGS request across a Forest trust and receive a TGS for a user that gives you access to an explicitly shared service. e.g. if a CIFS service is setup on an external forest for your finance team, you can successfully request a TGS for this service by impersonating a finance user and access it.
 
 Note, that you would of course be able to access this resource with the user creds anyway, if you have them, however user creds may change, but the Trust Key will almost never be changed, meaning that you can use this to access remote resources even after the user account may have had their password changed.

## Why would you do this?
So you have Domain Admin? Big deal....Enterprise Admin is where all the cool kids hang.

