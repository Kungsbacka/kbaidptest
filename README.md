# kbaidptest

Test app that can act as an SP in a SAML federation. Add IdP configuration to appsettings.json under "Saml2".

To set up a Relying Party in ADFS you can do as follows:

```PowerShell
# Issue all incoming claims for test purposes. Do *not* do this in production!
$rules = @'
@RuleName = "Issue all claims"
c:[]
 => issue(claim = c);
'@

$appUrl = 'kbaidptest.example.com'
$configName = 'example' # Use the same name in appsettings.json for this IdP

$samlEndpoints = @()

$samlEndpoints += New-AdfsSamlEndpoint -Binding POST -Protocol SAMLAssertionConsumer -Uri "https://$appUrl/Auth/AssertionConsumerService/$configName" -IsDefault $true

# Logout doesn't work in the app, but it might in the future
$samlEndpoints += New-AdfsSamlEndpoint -Binding Redirect -Protocol SAMLLogout -Uri "https://$appUrl/Auth/LoggedOut/$configName" -IsDefault $true

Add-AdfsRelyingPartyTrust -Name 'kbaidptest' -Identifier 'http://kbaidptest' -SamlEndpoint $samlEndpoints -AccessControlPolicyName 'Permit Everyone' -IssuanceTransformRules $rules
```
