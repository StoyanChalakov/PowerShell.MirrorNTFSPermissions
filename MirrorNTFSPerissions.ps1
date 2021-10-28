########################################################################################################################
# Synopsis: Permission mirroring, based on a CSV file with matching SamAccountNames from 2x domains.
# Title: MirrorNTFSPermissions.ps1
# Description: The script traverses a ntfs folder path on a certian file server, located in the so called Source domain, 
# exports the permissions for each folder and then mirrors the permissions only for the users located in the CSV file.
# Init Release: 23.08.2021
# Last Update:  27.10.2021
# Version:      1.0    #
##########################################################################################################################

#Set execution policy mode
Set-ExecutionPolicy -ExecutionPolicy Bypass
#Clear error
$error.clear()

#region Modules
#Import Module
Write-Log -Type INFO -Text "Importing Module Active Directory"
Import-Module ActiveDirectory
#endregion

#region Variables
$ErrorActionPreference = "Stop"
[string]$FolderPath = "C:\FolderPerm" #The root folder (and its subfolders) where permnissions will be mirrored (Source Domain)
[string]$DestDomNetBIOS = "DEST_DOMAIN" #NetBIOS name of the domain in which the targeted users reside (the users, who should get the ntfs permissions)
[string]$DestDomSearchBase = "DC=DEST_DOMAIN,DC=COM" #Destination Domain Search Base
[string]$DestDomainDC = "DomainController.dest_domain.com" #Domain Controller from the destination domain in which the target users are. 
[string]$CSVPath = "C:\Users\Users.csv" #Path to the CSV file containing the two SamAccountName user columns (Source Domain)
[string]$LogPath = "C:\Logs\Logging" #Path to log file (Source Domain)
#endregion

#region Functions
function Write-Log {
    [CmdletBinding()]
    param
    (
        [ValidateSet('INFO', 'WARNING', 'ERROR')]
        [string]$Type,
        [string]$Text
    )
    # Set the logging path
    if (!(Test-Path -Path $logPath)) {
        try {
            $null = New-Item -Path $logPath -ItemType Directory
            Write-Verbose ("Path: ""{0}"" was created." -f $logPath)
        } catch {
            Write-Verbose ("Path: ""{0}"" couldn't be created." -f $logPath)
        }
    } else {
        Write-Verbose ("Path: ""{0}"" already exists." -f $logPath)
    }
    [string]$logFile = '{0}\{1}_{2}.log' -f $logPath, $(Get-Date -Format 'yyyyMMdd'), $LogfileName
    $logEntry = '{0}: <{1}> <{2}> <{3}> {4}' -f $(Get-Date -Format dd.MM.yyyy-HH:mm:ss), $Type, $Text
    Add-Content -Path $logFile -Value $logEntry
}
#endregion

#Read the users and store them
Write-Log -Type INFO -Text "Reading the Users from the CSV file"
$Users = Import-Csv -Path $CSVPath -Delimiter ","

#Create a hash table with the values (Key = Source, Value = Destination)
Write-Log -Type INFO -Text "Building a hash table to store the users"
$HashTable=@{}
foreach($row in $Users)
{
  $HashTable[$row.Source]=$row.Destination
}

#Get folder structure
Write-Log -Type INFO -Text "Getting all the folders"
$Folders = Get-ChildItem -Directory -Path $FolderPath -Recurse -Force

#Traverse folders
Foreach ($Folder in $Folders) {

     #Get Folder ACL
     $FolderAcl = Get-Acl -Path $Folder.FullName
     Write-Log -Type INFO -Text "Working on folder $($Folder.Name)"

     foreach ($Access in $FolderAcl.Access) {

         #Get the source user Identity
         $SourceUser = $Access.IdentityReference

        if ($SourceUser.Value  -ne "CREATOR OWNER") {

            #Get the index of the separator
            $index = $SourceUser.Value.IndexOf("\")

             #Trim the user
             $SourceUserSAM = $SourceUser.Value.Substring($index+1)

            if ($HashTable.ContainsKey($SourceUserSAM)) {

            #Get the corrsponding ASH userfrom the hashtable
            $DestUserRAW = $Hashtable.GetEnumerator() | where {$_.Key -eq $SourceUserSAM}
            $DestUserSAM = $DestUserRAW.Value
            Write-Log -Type INFO -Text "Working with user $($DestUserSAM)"

        try {
            #Get the user from the other domain
            $DestUserFull =  Get-ADUser -Filter {samAccountName -eq $DestUserSAM} -SearchBase $DestDomSearchBase -Server $DestDomainDC
        } catch {
            $ErrorMessage = $_.Exception.Message
            $FailedItem = $_.Exception.ItemName
            Write-Log -Type ERROR -Text "$ErrorMessage"
            Write-Log -Type ERROR -Text "$FailedItem"
            }

            Write-Log -Type INFO -Text "Setting the permissions for user $($DestUserFull.Name)"

            $FileSystemRights1 = $Access.FileSystemRights
            $AccessControlType1 = $Access.AccessControlType
            $IdentityReference1 = $Access.IdentityReference
            $InheritanceFlags1 = $Access.InheritanceFlags
            $PropagationFlags1 = $Access.PropagationFlags

            try {
                    #Generate the access rule for the new account
                    $NewUserACL = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($DestUserFull.SID,"$FileSystemRights1","$InheritanceFlags1","$PropagationFlags1","$AccessControlType1")
                    #Add the access rule on the current folder ACL
                    $FolderAcl.SetAccessRule($NewUserACL)

                    #Set the access rule on the current folder
                    Set-acl -Path $Folder.FullName -AclObject $FolderAcl
                    Write-Log -Type INFO -Text "Permissions on $($Folder.FullName) set"
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    $FailedItem = $_.Exception.ItemName
                    Write-Log -Type ERROR -Text "$ErrorMessage"
                    Write-Log -Type ERROR -Text "$FailedItem"
            }

          #Clear Flag Variables
          Remove-Variable  FileSystemRights1,AccessControlType1,IdentityReference1,InheritanceFlags1,PropagationFlags1
         }

       }

     }

   }
