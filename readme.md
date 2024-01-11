# Fido2.NetFramework

The goal of this project is to port the [fido2-net-lib](https://github.com/passwordless-lib/fido2-net-lib) to .NET Framework 4.7.2
The **fido2-net-lib** targets .NET6 which makes it unusable in .NET Framework 4.7.2 and still, there are multiple systems targeting
.NET 4.X that would benefit from employing the Fido2 protocol.

## Disclaimer

This is a work in progress, I'd be grateful for all input provided by the community.

## Current status (2023-11-30)

* demo app works, attestation/assertion work 
* 282 unit tests pass, 1 doesn't pass as .NET.Framework doesn't support specific certificate feature

## Demo application

The demo application (`Fido.NetFramework.Demo`) requires a database. The database is configured in the `web.config`, in the `appSettings` section

```
  <appSettings>
    ...
    <add key="ConnectionStrings:FidoDbContext" value="server=.\sql2019;database=webauthn;integrated security=true" />
  </appSettings>
```

This should point to an **existing, empty** database (no tables). The Entity Framework is configured to automatically create the database schema based on the model.
When the application is run for the first time and a first query is executed against the database, all the required tables are created

## Nuget

[Fido2.NetFramework](https://www.nuget.org/packages/Fido2.NetFramework/)

## Version history

* 0.5.0 - important unit tests work
* 0.3.0 - EC signatures work
* 0.2.0 - downgraded to .NET 4.7.2 for compatibility reasons
* 0.1.0 - initial release