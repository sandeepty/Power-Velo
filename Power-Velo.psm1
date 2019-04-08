#Velocloud powershell commandlets start here
#Logging into velocloud orchestarator
function Connect-vcoOperator
{
     <#
        .DESCRIPTION
        Connect and Login to the VCO as Operator

        .EXAMPLE
        Connect-vcoOperator -Server <vco ip> -Username super@velocloud.net -Password <Password>

        .NOTES
        Version:      Beta 1.0
        Author:       Sandeep TY (sty@vmware.com)
        This is just an example function.
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string] $Server,
        [Parameter(Mandatory=$true)]
        [string] $Username,
        [Parameter(Mandatory=$true)]
        [string] $Password
    )

    Process
    {
        $Global:RESTUrl = 'https://' + $Server + '/portal/rest/' 
        $Url = $RestUrl + 'login/operatorLogin'
        Write-Host $Url

$Body = @{
    'username' = $Username
    'password' = $Password
 
  }
  Write-Host $Username
  Write-Host $Password
try {
    Invoke-RestMethod   -Uri $Url  -Method Post -Body $Body -SkipCertificateCheck -SessionVariable websession
  
}
catch {
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription 
}
$cookies = $websession.Cookies.GetCookies($Url) 
$Global:Session = $websession 

Write-Host "$($cookies[0].name) = $($cookies[0].value)"}

}


#Provisioning a new egde-----------------------
function New-EdgeProvision
{

    <#
        .DESCRIPTION
        Create/Provision a New edge
        .PARAMETER ConfigurationId
        This is the profileID for the edge
        .EXAMPLE
         New-EdgeProvision -Name Edge-001 -ConfigurationId 10 -EnterpriseId 1 -Model vmware

        .NOTES
        Version:      Beta 1.0
        Author:       Sandeep TY (sty@vmware.com)
        This is just an example function.
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int] $EnterpriseId,
        [Parameter(Mandatory=$true,HelpMessage = "enter the profile id for the edge")]
        
        [int] $ConfigurationId,
        [Parameter(Mandatory=$true)]
        [string] $Name,
        [Parameter(Mandatory=$true)]
        [string] $Model
    )

    Process
    {
        $EdgeUrl = $RestUrl +'edge/edgeProvision'

$Edgebody = @{
    'enterpriseId' = $EnterpriseId
    'configurationId'= $ConfigurationId
    'name'= $Name
    'modelNumber'= $Model
}

$RBODY = ConvertTo-Json -InputObject $Edgebody

Write-Host $RBODY
Write-Host $websession

Invoke-RestMethod   -Uri $EdgeUrl  -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session
    }
}

#Getting All enterprise edges----------------------------------------

function Get-EnterPriseEdges
{

    <#
        .DESCRIPTION
        Gets all the edges of specified enterprise
       
        .EXAMPLE
         New-EdgeProvision -Name Edge-001 -ConfigurationId 10 -EnterpriseId 1 -Model vmware

        .NOTES
        Version:      Beta 1.0
        Author:       Sandeep TY (sty@vmware.com)
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int] $EnterpriseId
       
    )

    Process
    {
        $EnterPriseEdgesUrl = $RestUrl +'enterprise/getEnterpriseEdges'

$Edgebody = @{
    'enterpriseId' = $EnterpriseId

}

$RBODY = ConvertTo-Json -InputObject $Edgebody

Write-Host $RBODY
Write-Host $websession

Invoke-RestMethod   -Uri $EnterPriseEdgesUrl  -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session
    }
}

#Getting Profiles used by an enterprise---------------------------------------------------------------------------
function Get-EnterPriseProfiles
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int] $EnterpriseId
       
    )

    Process
    {
        $EnterPriseEdgesUrl = $RestUrl +'enterprise/getEnterpriseConfigurations'

$Edgebody = @{
    'enterpriseId' = $EnterpriseId

}

$RBODY = ConvertTo-Json -InputObject $Edgebody

Write-Host $RBODY
Write-Host $websession

Invoke-RestMethod   -Uri $EnterPriseEdgesUrl  -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session
    }
}



#Getting Routed interface IP addresses----------------------------------------------------------------
function Get-EdgeRoutedInterfaceaddress
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int] $EdgeId,
        [Parameter(Mandatory=$true)]
        [int] $EnterPriseId
       
    )

    Process
    {
        $EdgeUrl = $RestUrl +'edge/getEdgeConfigurationStack'

$Edgebody = @{
    'edgeId' = $EdgeId
    'enterpriseId'=$EnterPriseId

}

$RBODY = ConvertTo-Json -InputObject $Edgebody
Write-Host $EdgeUrl
Write-Host $RBODY
Write-Host $websession

#Invoke-RestMethod   -Uri $EdgeUrl  -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session 
$JSON = Invoke-WebRequest -Uri $EdgeUrl -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session
$DATA = ConvertFrom-Json $JSON
$DATA."modules"."data"."routedInterfaces" |Format-Table name,@{Label = "Type"; Expression = { $_.addressing.type}},@{Label = "CIDR-Prefix"; Expression = { $_.addressing.cidrPrefix}},@{Label = "IP"; Expression = { $_.addressing.cidrIP}},@{Label = "Netmask"; Expression = { $_.addressing.netmask}},@{Label = "Gateway"; Expression = { $_.addressing.gateway}}




    }
}

#Getting LAN interfaces IP addresses----------------------------------------------------------------

function Get-EdgeLANInterfaceaddress
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int] $EdgeId,
        [Parameter(Mandatory=$true)]
        [int] $EnterPriseId
       
    )

    Process
    {
        $EdgeUrl = $RestUrl +'edge/getEdgeConfigurationStack'

$Edgebody = @{
    'edgeId' = $EdgeId
    'enterpriseId'=$EnterPriseId

}

$RBODY = ConvertTo-Json -InputObject $Edgebody
Write-Host $EdgeUrl
Write-Host $RBODY
Write-Host $websession

#Invoke-RestMethod   -Uri $EdgeUrl  -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session 
$JSON = Invoke-WebRequest -Uri $EdgeUrl -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session
$DATA = ConvertFrom-Json $JSON
$DATA."modules"."data"."lan"."networks" | Format-Table name,space,advertise,netmask,cidrPrefix,cidrIP,vlanId

    }
}



#Getting  enterprise Details----------------------------------------------------------------

function Get-EnterPrise
{

    <#
        .DESCRIPTION
        Gets enterprise details
       
        .EXAMPLE
        Get-EnterPrise -EnterpriseId 1
        .NOTES
        Version:      Beta 1.0
        Author:       Sandeep TY (sty@vmware.com)
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int] $EnterpriseId
       
    )

    Process
    {
        $EnterPriseEdgesUrl = $RestUrl +'enterprise/getEnterprise'

$Edgebody = @{
    'enterpriseId' = $EnterpriseId

}

$RBODY = ConvertTo-Json -InputObject $Edgebody

Write-Host $RBODY
Write-Host $websession

Invoke-RestMethod   -Uri $EnterPriseEdgesUrl  -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session
    }
}




#Getting  enterprise addresses----------------------------------------------------------------

function Get-EnterPriseAddresses
{

    <#
        .DESCRIPTION
        Retrieve the public IP address information for the management and control entities associated with this enterprise, including Orchestrator(s), Gateway(s), and datacenter(s).
       
        .EXAMPLE
        Get-EnterPriseAddresses -EnterpriseId 1
        .NOTES
        Version:      Beta 1.0
        Author:       Sandeep TY (sty@vmware.com)
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int] $EnterpriseId
       
    )

    Process
    {
        $EnterPriseEdgesUrl = $RestUrl +'enterprise/getEnterpriseAddresses'

$Edgebody = @{
    'enterpriseId' = $EnterpriseId

}

$RBODY = ConvertTo-Json -InputObject $Edgebody

Write-Host $RBODY
Write-Host $websession

Invoke-RestMethod   -Uri $EnterPriseEdgesUrl  -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session
    }
}
   

#Enterprise LogIn ......................



function connect-vcoEnterpriselogin
{

    <#
        .DESCRIPTION
        Connect and Login to the VCO as Enterprise user

        .EXAMPLE
        connect-vcoEnterpriselogin <vco ip> -Username user@email.com -Password <Password>

        .NOTES
        Version:      Beta 1.0
        Author:       Sandeep TY (sty@vmware.com)
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string] $Server,
        [string] $Username,
        [string] $Password
    )

    Process
    {
        $Global:RESTUrl = 'https://' + $Server + '/portal/rest/' 
        $Url = $RestUrl + 'login/enterpriseLogin'
        Write-Host $Url

$Body = @{
    'username' = $Username
    'password' = $Password
 
  }
  Write-Host $Username
  Write-Host $Password
try {
    Invoke-RestMethod   -Uri $Url  -Method Post -Body $Body -SkipCertificateCheck -SessionVariable websession
  
}
catch {
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription 
}
$cookies = $websession.Cookies.GetCookies($Url) 
$Global:Session = $websession 

Write-Host "$($cookies[0].name) = $($cookies[0].value)"}

}


#Getting Edge interface OSPF details----------------------------------------------------------------
function Get-EdgeOspf
{

    <#
        .DESCRIPTION
        Get OSPF details of the interfaces

        .EXAMPLE

        .NOTES
        Version:      Beta 1.0
        Author:       Sandeep TY (sty@vmware.com)
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int] $EdgeId,
        [int] $EnterPriseId
       
    )

    Process
    {
        $EdgeUrl = $RestUrl +'edge/getEdgeConfigurationStack'

$Edgebody = @{
    'edgeId' = $EdgeId
    'enterpriseId'=$EnterPriseId

}

$RBODY = ConvertTo-Json -InputObject $Edgebody
Write-Host $EdgeUrl
Write-Host $RBODY
Write-Host $websession

#Invoke-RestMethod   -Uri $EdgeUrl  -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session 
$JSON = Invoke-WebRequest -Uri $EdgeUrl -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session
$DATA = ConvertFrom-Json $JSON
Write-Host "Getting interface OSPF details"
$DATA."modules"."data"."routedInterfaces" |Format-Table name,@{Label = "Ospf Enabled"; Expression = { $_.ospf.enabled}},@{Label = "Area"; Expression = { $_.ospf.area}},@{Label = "HelloTimer"; Expression = { $_.ospf.helloTimer}},@{Label = "DeadTimer"; Expression = { $_.ospf.deadTimer}},@{Label = "Cost"; Expression = { $_.ospf.cost}},@{Label = "MTU"; Expression = { $_.ospf.mtu}}




    }
}



#Get the alert configurations associated with an enterprise.----------------------------------------------------------------

function Get-EnterpriseAlertConfigurations
{

    <#
        .DESCRIPTION
       Get the alert configurations associated with an enterprise.
       
        .EXAMPLE
        Get-EnterpriseAlertConfigurations -EnterpriseId 1
        .NOTES
        Version:      Beta 1.0
        Author:       Sandeep TY (sty@vmware.com)
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int] $EnterpriseId
       
    )

    Process
    {
        $EnterPriseEdgesUrl = $RestUrl +'enterprise/getEnterpriseAlertConfigurations'

$Edgebody = @{
    'enterpriseId' = $EnterpriseId

}

$RBODY = ConvertTo-Json -InputObject $Edgebody

Write-Host $RBODY
Write-Host $websession

Invoke-RestMethod   -Uri $EnterPriseEdgesUrl  -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session
    }
}



#Gets past triggered alerts for the specified enterprise.----------------------------------------------------------------

function Get-EnterPriseAlerts
{

    <#
        .DESCRIPTION
        Gets past triggered alerts for the specified enterprise.
       
        .EXAMPLE
        Get-EnterPriseAlerts -EnterpriseId 1
        .NOTES
        Version:      Beta 1.0
        Author:       Sandeep TY (sty@vmware.com)
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int] $EnterpriseId
       
    )

    Process
    {
        $EnterPriseUrl = $RestUrl +'enterprise/getEnterpriseAlerts'

$Edgebody = @{
    'enterpriseId' = $EnterpriseId

}

$RBODY = ConvertTo-Json -InputObject $Edgebody

Write-Host $RBODY
Write-Host $websession

$JSON = Invoke-WebRequest -Uri $EnterPriseUrl  -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session
$DATA = ConvertFrom-Json $JSON  
$DATA."data" | Format-Table id,enterpriseId,edgeId,name,type,state

}
}
   

#Retrieve a list of the enterprise capabilities currently enabled/disabled on an enterprise (e.g. BGP, COS mapping, PKI, etc.)----------------------------------------------------------------

function Get-EnterpriseCapabilities
{

    <#
        .DESCRIPTION
        Retrieve a list of the enterprise capabilities currently enabled/disabled on an enterprise (e.g. BGP, COS mapping, PKI, etc.)
       
        .EXAMPLE
        Get-EnterpriseCapabilities -EnterpriseId 1
        .NOTES
        Version:      Beta 1.0
        Author:       Sandeep TY (sty@vmware.com)
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int] $EnterpriseId
       
    )

    Process
    {
        $EnterPriseEdgesUrl = $RestUrl +'enterprise/getEnterpriseCapabilities'

$Edgebody = @{
    'enterpriseId' = $EnterpriseId

}

$RBODY = ConvertTo-Json -InputObject $Edgebody

Write-Host $RBODY
Write-Host $websession

Invoke-RestMethod   -Uri $EnterPriseEdgesUrl  -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session
    }
}
   

#Get enterprise gateway handoff configuration.----------------------------------------------------------------

function Get-EnterpriseGatewayHandoff
{

    <#
        .DESCRIPTION
        Get enterprise gateway handoff configuration.
       
        .EXAMPLE
        Get-EnterpriseGatewayHandoff  -EnterpriseId 1
        .NOTES
        Version:      Beta 1.0
        Author:       Sandeep TY (sty@vmware.com)
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int] $EnterpriseId
       
    )

    Process
    {
        $EnterPriseEdgesUrl = $RestUrl +'enterprise/getEnterpriseGatewayHandoff'

$Edgebody = @{
    'enterpriseId' = $EnterpriseId

}

$RBODY = ConvertTo-Json -InputObject $Edgebody

Write-Host $RBODY
Write-Host $websession

Invoke-RestMethod   -Uri $EnterPriseEdgesUrl  -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session
    }
}


#Retrieve a list of all of the network allocations defined on the given enterprise.----------------------------------------------------------------

function Get-EnterpriseNetworkAllocations
{

    <#
        .DESCRIPTION
        Retrieve a list of all of the network allocations defined onthe given enterprise.
       
        .EXAMPLE
        Get-EnterpriseNetworkAllocations -EnterpriseId 1
        .NOTES
        Version:      Beta 1.0
        Author:       Sandeep TY (sty@vmware.com)
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int] $EnterpriseId
       
    )

    Process
    {
        $EnterPriseEdgesUrl = $RestUrl +'enterprise/getEnterpriseNetworkAllocations'

$Edgebody = @{
    'enterpriseId' = $EnterpriseId

}

$RBODY = ConvertTo-Json -InputObject $Edgebody

Write-Host $RBODY
Write-Host $websession

Invoke-RestMethod   -Uri $EnterPriseEdgesUrl  -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session
    }
}




#Get enterprise route advertisement, routing peferences and OSPF, BGP advertisement policy as configured in the Overlay Flow Control table..----------------------------------------------------------------

function Get-EnterpriseRouteConfiguration
{

    <#
        .DESCRIPTION
        Get enterprise route advertisement, routing peferences and OSPF, BGP advertisement policy as configured in the Overlay Flow Control table.
       
        .EXAMPLE
        Get-EnterpriseRouteConfiguration -EnterpriseId 1
        .NOTES
        Version:      Beta 1.0
        Author:       Sandeep TY (sty@vmware.com)
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int] $EnterpriseId
       
    )

    Process
    {
        $EnterPriseEdgesUrl = $RestUrl +'enterprise/getEnterpriseRouteConfiguration'

$Edgebody = @{
    'enterpriseId' = $EnterpriseId

}

$RBODY = ConvertTo-Json -InputObject $Edgebody

Write-Host $RBODY
Write-Host $websession

$JSON = Invoke-WebRequest -Uri $EnterPriseEdgesUrl  -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session
$DATA = ConvertFrom-Json $JSON  


Write-Host "Edge-OSPF"
$DATA."data"."edge"."ospf" | Format-Table 
Write-Host "Edge-BGP"
$DATA."data"."edge"."bgp" | Format-Table 
Write-Host "Edge-Other"
$DATA."data"."edge"."assigned" | Format-Table 


Write-Host "HUB-OSPF"
$DATA."data"."hub"."ospf" | Format-Table 
Write-Host "HUB-BGP"
$DATA."data"."hub"."bgp" | Format-Table 
Write-Host "HUB-Other"
$DATA."data"."hub"."assigned" | Format-Table 

Write-Host "PartnerGateway-BGP"
$DATA."data"."partnerGateway"."bgp" | Format-Table 
Write-Host "PartnerGateway-Other"
$DATA."data"."partnerGateway"."assigned" | Format-Table 

Write-Host "Routing Preference"
$DATA."data"."routingPreference"| Format-Table 
    }
    }


#Get the network service JSON objects defined for an enterprise.---------------------------------------------------------------------------
function Get-EnterpriseServices
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int] $EnterpriseId
       
    )

    Process
    {
        $EnterPriseEdgesUrl = $RestUrl +'/enterprise/getEnterpriseServices'

$Edgebody = @{
    'enterpriseId' = $EnterpriseId

}

$RBODY = ConvertTo-Json -InputObject $Edgebody

Write-Host $RBODY
Write-Host $websession

Invoke-RestMethod   -Uri $EnterPriseEdgesUrl  -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session
    }
}





#Creates a new enterprise, which is owned by the operator..----------------------------------------------------------------

function New-Enterprise
{

    <#
        .DESCRIPTION
        Creates a new enterprise, which is owned by the operator.
       
        .EXAMPLE
        New-Enterprise -EnterpriseName sdk-module -ConfigurationId 1 -NetworkId 0 -UserName <username> -Password <password>
        .NOTES
        Version:      Beta 1.0
        Author:       Sandeep TY (sty@vmware.com)
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string] $EnterpriseName,
        [Parameter(Mandatory=$true)]

        [string]$NetworkId,
        [Parameter(Mandatory=$true)]
        [string]$ConfigurationId,
        [Parameter(Mandatory=$true)]
        [string]$UserName,
        [Parameter(Mandatory=$true)]
        [string]$Password
       
    )

    Process
    {
        $EnterPriseEdgesUrl = $RestUrl +'enterprise/insertEnterprise'

$Edgebody = @{
        'name' = $EnterpriseName
    
        'networkId' =  $NetworkId
           'configurationId' =  $ConfigurationId
           'user' = @{ 
               'username' = $UserName
               'password' = $Password  
            }
           'enableEnterpriseDelegationToOperator' =  True
           'enableEnterpriseUserManagementDelegationToOperator' = True

}

$RBODY = ConvertTo-Json -InputObject $Edgebody



Write-Host $RBODY
Write-Host $websession

Invoke-RestMethod   -Uri $EnterPriseEdgesUrl  -Method Post -Body $RBODY -SkipCertificateCheck -WebSession $Session
    }
}
   
