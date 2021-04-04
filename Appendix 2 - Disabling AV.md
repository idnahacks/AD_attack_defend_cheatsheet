# Disabling AV
## Defender
The below commands assume that tamper protection is not enabled.
- Disable AMSI
`Set-MpPreference -DisableIOAVProtection $true`
 - Disable AV Protection
`Set-MpPreference -DisableRealtimeMonitoring $true`