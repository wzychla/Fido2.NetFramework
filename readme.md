# Fido2.NetFramework

The goal of this project is to port the [fido2-net-lib](https://github.com/passwordless-lib/fido2-net-lib) to .NET Framework 4.7.2
The **fido2-net-lib** targets .NET6 which makes it unusable in .NET Framework 4.7.2 and still, there are multiple systems targeting
.NET 4.X that would benefit from employing the Fido2 protocol.

## Disclaimer

This is a work in progress, I'd be grateful for all input provided by the community.

## Current status (2023-10-20)

* demo app works, attestation/assertion work at least on my phone
* 134 unit tests passed, 3 failed, some important still commented out

## Nuget

Soon

## Version history

* 0.2.0 - downgraded to .NET 4.7.2 for compatibility reasons
* 0.1.0 - initial release