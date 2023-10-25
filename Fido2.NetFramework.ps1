# /bin/release
$dll     = Resolve-Path "./Fido2.NetFramework/bin/Release/Fido2.NetFramework.dll"
$version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($dll).FileVersion

# utwórz folder
$path = ("./Fido2.NetFramework/bin/" + $version)

New-Item -ItemType Directory -Force -Path $path
New-Item -ItemType Directory -Force -Path ($path + "/lib")
New-Item -ItemType Directory -Force -Path ($path + "/lib/net472")

Copy-Item $dll ($path + "/lib/net472")

# nuspec
$nuspec = ($path + "/Fido2.NetFramework.nuspec")
$contents = @"
<?xml version="1.0"?>
<package>
  <metadata>
    <id>Fido2.NetFramework</id>
    <version>__VERSION</version>
    <authors>wzychla</authors>
	<dependencies>
		<group targetFramework="net462">
			<dependency id="BouncyCastle.Cryptography" version="2.2.1" />
			<dependency id="Newtonsoft.Json" version="13.0.3" />			
			<dependency id="System.Formats.Asn1" version="7.0.0" />			
			<dependency id="System.Formats.Cbor" version="7.0.0" />			
			<dependency id="System.IdentityModel.Tokens.Jwt" version="7.0.2" />			
		</group>
	</dependencies>
    <projectUrl>https://github.com/wzychla/Fido2.NetFramework</projectUrl>
	<repository type="git" url="https://github.com/wzychla/Fido2.NetFramework" />
    <requireLicenseAcceptance>true</requireLicenseAcceptance>
	<license type="expression">MIT</license>
    <description>Fido2.NetFramework. Net.Framework port of fido2-net-lib.</description>
    <copyright>Copyright 2023 Wiktor Zychla</copyright>
    <tags>fido2</tags>
  </metadata>
  <files>
	<file src="lib/net472/Fido2.NetFramework.dll" target="lib/net472/Fido2.NetFramework.dll" />  
  </files>
</package>
"@

$contents = $contents -replace "__VERSION", $version

New-Item -ItemType File -Path $nuspec -value $contents

# spakuj
Set-Location -Path $path
nuget pack

Set-Location -Path "../../.."