# Disabling AV
## Defender
 - Disable AMSI
`Set-MpPreference -DisableIOAVProtection $true`
 - Disable AV Protection
`Set-MpPreference -DisableRealtimeMonitoring $true`