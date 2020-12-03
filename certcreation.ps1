#This is to create new certificates


$ReqFullName='John Smith'  #######needs variable -> this is the requester's name in order to be able to address the person requesting the cert #######
$x=$ReqFullName.IndexOf(" ")-1 #get's the length of the requester's first name
$ReqName=$ReqFullName[0..$x] -join "" #does not need a variable passed in, it uses the $ReqFullName variable to get the requester's first name
$ReqEmail='johnsmith@somecompany.org' #######needs variable -> Needs to be team's email in case requester ceases to work at somecompany, the email of the team s/he used to work for would still be available.###
$DNS="somedns.somecompany.org, somedns2.somecompany.org"  #######Needs variable -> This variable get's the Subject Alternative names entered by the requester separated by a comma

$CertName = "certtest.somecompany.org" ######Needs variable -> Certificate name, this will be used in otder to generate the certificate and the multiple files #####


$Signature = '$Windows NT$' 
$CA= "SomeCompanyServerCA" # This has to be the Certificate Authority server
$CAComp= "CAComp.somecompany.org" #this variable needs to be changed to you CA Comp
$year=(Get-Date -UFormat "%Y") #Used for friendly name
$FriendlyName="$CertName-$year" #Creates a friendly name with the certificate name and the year it was created

##Everything after this line creates paths for files that will be used in the script
$CSRPath = "C:\path\$($CertName).csr"  
$CERPath= "C:\path\$($CertName).cer"
$INFPath = "C:\path\$($CertName).inf"
$RequestIdPath="C:\path\RequestID.txt"
$PFXPath= "C:\path\$($CertName).pfx"
$RSPPath= "C:\path\$($CertName).rsp"
$PassFile= "C:\path\$($CertName)PASS.txt"
$OutFile= "C:\path\$($CertName)Out.txt"


##start of try/catch block
try{
	#####editing dns to add correctly
	$DNS=$DNS.Trim().replace(", ", ",").replace(" ",",").replace(" ,",",").trimend(",").trimstart(",")
	$charcount=($dns.tochararray() | where-object{$_ -eq ","} |measure-object).count
	$dnsarr=$dns.split(",")
	$len=$dnsarr.length
	$dnsstring="dns="+$dnsarr[0]
	for($i=1; $i -le $len-1; $i++){
	$dnsstring=$dnsstring+"&dns="+$dnsarr[$i]
	}

	###END of DNS editting

	$SAN=$dnsstring
	#Write-Host " Creating CertificateRequest(CSR) for $CertName `r "

	#Writing .inf file
	if($SAN -eq "dns="){
$INF =
@"
[Version]
Signature= "$Signature" 
 
[NewRequest]
Subject = "CN=$CertName"
FriendlyName=$FriendlyName
KeyLength=2048
MachineKeySet=True
Exportable=True
ExportableEncrypted=true

[RequestAttributes]
CertificateTemplate=CISSL-NonDomain-Auto
	
"@
	}else{ #writes inf file if it finds an input in $DNS
$INF =
@"
[Version]
Signature= "$Signature" 

[NewRequest]
Subject = "CN=$CertName"
FriendlyName=$FriendlyName
KeyLength=2048
MachineKeySet=True
Exportable=True
ExportableEncrypted=true

[RequestAttributes]
CertificateTemplate=CISSL-NonDomain-Auto
SAN=$dnsstring
"@
	}

	Write-Output "Certificate Request is being generated `r " > $OutFile
	$INF | Out-File -FilePath $INFPath -force 
	
	

	#Creating a new certificate request for the machine

	#Checks if file already exists. If it does, deletes it and keeps running
	if(Test-Path $CSRPath){ remove-item $CSRPath }
	certreq -new -machine $INFPath $CSRPath |Add-Content $OutFile


	#Write-Output "Certificate Request has been generated" 

	#Submits certificate request
	#write-host "Sending Certificate Request"

	#Checks if file already exists. If it does, deletes it and keeps running
	if(Test-Path $CERPath){remove-item $CERPath}
	if(Test-Path $RSPPath){remove-item $RSPPath}
	certreq -submit -adminforcemachine -config "$CAComp\$CA" -attrib "CertificateTemplate:someCertificateTemplate" $CSRPath $CERPath|Out-File -FilePath $RequestIdPath -force
	
	#getting request id
	$RequestID= get-content $RequestIDPath -TotalCount 1
	$RequestID= $RequestID.replace('RequestId: ','')
	write-output "Request ID= " $RequestID |Add-Content $OutFile

	##waits for approval on the request id, this time will be shorter once we implement autoapprove
	#Write-Host "Waiting for approval on RequestID $Requestid"
	Start-Sleep -s 6
	#Write-Host "Request has been approved"

	#Retrieve CER file in order to accept it later  -- This isn't necessary unless the certificate has an approver
	#Write-Host "Retrieving CER file"
	#certreq -retrieve -adminforcemachine -config "$CAComp\$CA" $requestid $CERPath

	#Write-Output "Certificate retrieved succesfully"

	#removes files that are no longer needed
	Remove-Item -path $CSRPath
	Remove-Item -path $INFPath
	Remove-Item -path $RequestIdPath

	#Accepts certficate and adds it to certificate store
	#Write-Output "Accepting certificate"
	certreq -accept -machine $CERPath 

	#Write-Output "Certificate accepted"


	##Export certificate
	#Write-Output "Exporting certificate"
	Set-Location cert:\path
	
	#generating random password
	$asci = [char[]]([char]33..[char]95) + ([char[]]([char]97..[char]126)) 
	$weak = (1..$(Get-Random -Minimum 15 -Maximum 17) | % {$asci | get-random}) -join “” 
	$password=ConvertTo-SecureString -string $weak –asplaintext -force 

	#getting thumbprint
	$Thumbprint = (Get-ChildItem -Path Cert:\Path | Where-Object {$_.Subject -match "CN=$Certname"}).Thumbprint; 
	write-output "Thumbprint =" $thumbprint |Add-Content $OutFile
	$x=$thumbprint.length
	if([int]$x -eq 40){
		Export-PfxCertificate -cert $thumbprint -filepath $PFXPath -password $password |Add-Content $OutFile
	}else {
		if([int]$x -gt 0){
			$y=$x-1
			$thumbprint=$thumbprint[$y..$x] -join ""
			Export-PfxCertificate -cert $thumbprint -filepath $PFXPath -password $password	|Add-Content $OutFile
	
		}else{
			Export-PfxCertificate -cert $thumbprint -filepath $PFXPath -password $password |Add-Content $OutFile
		}
	}

	###store, return expiration date CMDB -> Store expiration date in Service now so an email will be sent out when certificate is about to expire
	$expDate=((Get-ChildItem -Path $Thumbprint).NotAfter).ToString("yyyy-MM-dd")
	write-output "Expiration date is= " $expDate |Add-Content $OutFile
	##store thumbprint -> in case we need to look back at the certificate and/or retrieve it

	write-output "$weak" > $PassFile
	remove-item -path $CERPath
	remove-item -path $RSPPath
    $todaysdate= Get-Date -format yyyy-MM-dd

	##store PFX file in service now so requester can retrieve their file from there, once that's done, delete file.
	##############################################
	#####  ADD NEW RECORD THEN ATTACH FILE   #####
	##############################################

	# Eg. User name="admin", Password="admin" for this code sample.
	$user =  userName###############change user
	$pass =  Password###############change password

	# Build auth header
	$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user, $pass)))

	# Set proper headers
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add('Authorization',('Basic {0}' -f $base64AuthInfo))
	$headers.Add('Accept','application/json')
	$headers.Add('Content-Type','application/json')

	#Define instance and table names
	$instanceName = "someCompanySandbox"
	$tableName = "someCompany_Cert_TableName"

	# Specify endpoint URI for creating new record
	$newRecordURI = "https://$($instanceName).service-now.com/api/now/table/$($tableName)"

	# Specify HTTP method
	$method = "POST"

	$body = @{
	'short_description' = 'SomeCompany Issued Certificate'
	'owned_by' =$ReqFullName
	'name'=$CertName
	'u_expires'=$expDate
	'dns_domain'=$DNS
	'u_issuer'='SomeCompany'
    'u_expiration_notification'='true'
    'u_valid_from'=$todaysdate
	}

	$bodyJson = $body | ConvertTo-Json

	# Send HTTP request
	$response = Invoke-WebRequest -Headers $headers -Method $method -Uri $newRecordURI -Body $bodyJson

	# Take response and get at the fields just created:
	$response2 = $response.Content | ConvertFrom-Json

	#Capture the sysID of the newly created record
	$newRecordSysID = $response2.result.sys_id

	##############################################
	#####         FILE UPLOAD                #####
	##############################################

	# Specify endpoint URI for attaching a file
	
	$recordSysID = $newRecordSysID
	$fileName = "$($CertName).pfx"
	
	$uriForFileAttach = "https://$($instanceName).service-now.com/api/now/attachment/file?table_name=$($tableName)&table_sys_id=$($recordSysID)&file_name=$($fileName)"

	# Specifiy file to attach
	$fileToAttach = "$($PFXPath)"

	# Specify HTTP method (POST, PATCH, PUT)
	$method = "POST"

	# Send HTTP request
	$response = Invoke-WebRequest -Headers $headers -Method $method -Uri $uriForFileAttach -InFile $fileToAttach


	##############################################
	#####          SEND EMAIL                #####
	##############################################
	
	$From='email@somecompany.org'
	$To=$ReqEmail #requster's team's email
	$Subject='Certificate Renewal'
	$Body='Hi {0}, <br/>Your certificate has been succesfully renewed and is waiting for you in ServiceNow, ready to be imported and installed. Your password is {1} . <br/><br/>Thank you, <br/>' -f $reqname, $weak
	$SMTPServer='smtp.somecompany.org'


	Send-MailMessage -From $From -To $To -Subject $Subject -BodyAsHTML $Body -SMTPServer $SMTPServer

	Remove-Item $OutFile
	Remove-Item $PFXPath
	Remove-Item $PassFile
}catch{
	write-output "Error occurred, everything stopped"
	$_ |Add-Content $OutFile
    
    #Sends error email
    $From='email@somecompany.org'
	$To='errorEmail@somecompany.org'
    $Subject='Certificate Renewal'
    $Attachment=$OutFile
	$Body='An error ocurred while creating the certificate. Pleas refer to the document attached to see the error(s).'
	$SMTPServer='smtp.somecompany.org'


	Send-MailMessage -From $From -To $To -Subject $Subject -BodyAsHTML $Body -SMTPServer $SMTPServer -Attachments $Attachment
    
	Remove-Item $OutFile
	
	break
}

