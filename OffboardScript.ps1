<#

OffboardScript.ps1
Written by Ben McCown 03/22/2018
Updated 03/26/2018

This script automates the offboarding procedure.

User Input Required:
Offboarded user last name (searches AD to display their account name so you don't have to look it up)
AD Account/Username from the above search
Select Domain by typing (1) for XXX or (2) for XXX
Yes or No confirmation to copy over the user's U drive (it will give you its size. say no if the folder is too big.)
NOTE: THIS WILL DELETE THEIR SOURCE FOLDER FROM \\user$ but only if the directories match exactly after the copy.

The script will:

Check if the active directory account exists. If so it will be moved to Terminated Users OU and disabled.
Check if the user's mailbox exists. If so, it will hide them from the Global Address List.
Check if a mail contact exists for the user. If so, it will be deleted.
Check if the user has a folder in \\user$ and copy it to \\_TermEmp\$user if so, will then delete the source folder
Check if the user has a mailbox. If so, it will export the PST, copy that PST to their _Termination folder, and clean itself up

To Add:
Run against a CSV in batch jobs
Run in XXX  domain

Revisions
03/22/2018 Creation. Added sequential steps listed above.
03/23/2018 Added conditions checking each step so they weren't running and throwing errors if stuff doesn't exist.
03/23/2018 Added commands to delete the user folder from shared storage
03/23/2018 Added commands for GPD domain
03/26/2018 Added last name search at beginning of script so you don't have to look up the user in AD Users/Computers

#>

# Self-elevate the script to run as administrator if required
# copied from a google search for "powershell self elevating script"
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
 if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
  $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
  Exit
 }
}

#Get-MailboxExportRequest -Status Failed | Get-MailboxExportRequestStatistics -IncludeReport | Format-List > C:\Offboarding\exportreport.txt

# Set variables
$year = Get-Date -Format FileDate
$cogshareroot = "\\user$\"
$nmlsshareroot = "\\user$\"
$cogsharetermroot = "\\_TermEmp\"
$gpdshareroot = "\\\user\"
$gpdDC = "XXX"

Write-Host "........................................." -Fore yellow -back black 
Write-host "...........OffboardScript.ps1............" -fore yellow -back black 
Write-Host "........................................." -Fore yellow -back black 
Write-Host ""

#Get user input
Write-Host ""
Write-Host "Enter the number corresponding to the user’s home folder location (1) Domain1, (2) Domain2, (3) Domain3: " -NoNewline -Fore Green -back black
$domainnumber = Read-Host
if (-Not ($domainnumber -eq "1" -or $domainnumber -eq "2" -eq $domainnumber -eq "3")) { exit }

Write-Host "Please enter the last name for the offboarding personnel: " -NoNewline -Fore Green -back black
$lastname = Read-Host

Write-Host "Searching for user. If no results are returned then no user was found." -ForegroundColor Yellow -back black
Switch ($domainnumber) {
    1 {
        Get-ADUser -Filter "Name -like '*${lastname}*'" -Properties * | Format-Table Name, SamAccountName, EmployeeID
    }
    2 {
        Get-ADUser -Server "$gpdDC" -Filter "Name -like '*${lastname}*'" -Properties * | Format-Table Name, SamAccountName, EmployeeID
    }
    3 {
        Get-ADUser -Filter "Name -like '*${lastname}*'" -Properties * | Format-Table Name, SamAccountName, EmployeeID
    }
    Default {
        Write-Host "Wrong Domain Entered. Cannot search for user." -ForegroundColor Red -back black
    }
}

write-host -nonewline "Continue? (Y/N) " -Fore Green -back black
$response = read-host
if ( $response -ne "Y" ) { exit }

Write-Host "Please enter the username for the correct offboarding personnel displayed above: " -NoNewline -Fore Green -back black
$user = Read-Host

# Start logging the output of this script
Start-Transcript -Path "C:\Offboarding\Log_$user$year.txt" -Append

# This snap in is required to have access to exchange commands so that we can work on mailboxes
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.Snapin;

# This section will calculate the size of a user's U drive.
# It will then display the results and confirm if you want to move it or not
# This input was put in place to prevent errors (if their U drive is massive maybe just move it by hand)

Write-Host "Calculating size of user's files." -ForegroundColor Yellow -back black

# This little section registers an external powershell script that I downloaded from the internet
# The external powershell script, Get-FolderSize.ps1 will check the directory size and give us a nice looking output
$env:path += ";c:\Offboarding"
Unblock-File "C:\Offboarding\Get-FolderSize.ps1"
. "C:\Offboarding\Get-FolderSize.ps1"

# If the directory exists then get the folder size and ask for user confirmation if we want to copy it or not
[bool] $copyfiles = $false
Switch ($domainnumber) 
        { 
        1 {
            if (Test-Path -Path "$cogshareroot$user") {
            Get-FolderSize -Path "$cogshareroot$user" -RoboOnly | Format-List

            if (Test-Path -Path "${cogsharetermroot}TermUsrsScripted_$year\$user") {
                Write-host "Note: Destination in _TermEmp already exists." -ForegroundColor Yellow -back black
            }

            Write-host "Would you like to move their files?" -ForegroundColor Green -back black
            Write-Host " (y/n) :" -Fore Yellow -back black -NoNewline
            $Readhost = Read-Host
            Switch ($ReadHost) 
            { 
            Y {
                $copyfiles = $true
            } 
            N {
                $copyfiles = $false
                Write-Host "Skipping file transfer. Please do so by hand from $cogshareroot to \\cog-chfs\software$\netadmin\_TermEmp" -ForegroundColor Yellow -back black
              } 
            Default {Write-Host "Skipping file transfer. Please do so by hand from $cogshareroot to \\cog-chfs\software$\netadmin\_TermEmp" -ForegroundColor Yellow -back black} 
            } 
            } else {
                Write-Host "User has no user folder in $cogshareroot" -Fore Yellow -back black
            }
          } 
        2 {
            if (Test-Path -Path "$gpdshareroot$user") {
                Get-FolderSize -Path "$gpdshareroot$user" -RoboOnly | Format-List

                if (Test-Path -Path "${cogsharetermroot}TermUsrsScripted_$year\$user") {
                    Write-host "Note: Destination in _TermEmp already exists." -ForegroundColor Yellow -back black
                }

                Write-host "Would you like to move their files?" -ForegroundColor Green -back black
                Write-Host " (y/n) :" -Fore Yellow -back black -NoNewline
                $Readhost = Read-Host
                Switch ($ReadHost) 
                { 
                Y {
                    $copyfiles = $true
                } 
                N {
                    $copyfiles = $false
                    Write-Host "Skipping file transfer. Please do so by hand from $gpdshareroot to \\cog-chfs\software$\netadmin\_TermEmp" -ForegroundColor Yellow -back black
                  } 
                Default {Write-Host "Skipping file transfer. Please do so by hand from $gpdshareroot to \\cog-chfs\software$\netadmin\_TermEmp" -ForegroundColor Yellow -back black} 
                } 
                } else {
                    Write-Host "User has no user folder in $gpdshareroot" -Fore Yellow -back black
                }
          }
        3 {
            if (Test-Path -Path "$nmlsshareroot$user") {

            Get-FolderSize -Path "$nmlsshareroot$user" -RoboOnly | Format-List

            if (Test-Path -Path "${cogsharetermroot}TermUsrsScripted_$year\$user") {
                Write-host "Note: Destination in _TermEmp already exists." -ForegroundColor Yellow -back black
            }

            Write-host "Would you like to move their files?" -ForegroundColor Green -back black
            Write-Host " (y/n) :" -Fore Yellow -back black -NoNewline
            $Readhost = Read-Host
            Switch ($ReadHost) 
            { 
            Y {
                $copyfiles = $true
            } 
            N {
                $copyfiles = $false
                Write-Host "Skipping file transfer. Please do so by hand from $nmlsshareroot to \\cog-chfs\software$\netadmin\_TermEmp" -ForegroundColor Yellow -back black
              } 
            Default {Write-Host "Skipping file transfer. Please do so by hand from $nmlsshareroot to \\cog-chfs\software$\netadmin\_TermEmp" -ForegroundColor Yellow -back black} 
            } 
            } else {
                Write-Host "User has no user folder in $nmlsshareroot" -Fore Yellow -back black
            }
          } 
        Default {Write-Host "Wrong Domain Entered. Skipping file transfer." -ForegroundColor Red -back black} 
        } 

Switch ($domainnumber) {
    1 {
        # If the AD account exists (boolean check with the Get-ADUser command) we'll move it to the correct OU and disable it
        Write-Host "Move to Terminated Users OU and disabling AD account." -Fore Yellow -back black
        if (Get-ADUser -Identity $user) {
            Get-ADUser -Identity $user | Move-ADObject -TargetPath 'OU=Terminated Users,DC=COG,DC=COGGOV,DC=LOCAL'
            $curuser = Get-ADUser -Identity $user -Properties Description
            $curdesc = $curuser.Description
            Get-ADUser -Identity $user | Set-ADUser -Enabled $false -Description "Disabled $year by script. $curdesc"
        } else {
            Write-Host "Error. No user found in Active Directory." -Fore red -back black
        }
    }
    2 {
        # If the AD account exists (boolean check with the Get-ADUser command) we'll move it to the correct OU and disable it
        Write-Host "Move to Terminated Users OU and disabling AD account." -Fore Yellow -back black
        if (Get-ADUser -Identity $user -Server "$gpdDC") {
            Get-ADUser -Identity $user -Server "$gpdDC" | Move-ADObject -Server "$gpdDC" -TargetPath 'OU=Terminated Users,DC=GPD,DC=COGGOV,DC=LOCAL'
            $curuser = Get-ADUser -Identity $user -Server "$gpdDC" -Properties Description
            $curdesc = $curuser.Description
            Get-ADUser -Identity $user -Server "$gpdDC"  | Set-ADUser -Server "$gpdDC" -Enabled $false -Description "Disabled $year by script. $curdesc"
        } else {
            Write-Host "Error. No user found in Active Directory." -Fore red -back black
        }
    }
    3 {
        # If the AD account exists (boolean check with the Get-ADUser command) we'll move it to the correct OU and disable it
        Write-Host "Move to Terminated Users OU and disabling AD account." -Fore Yellow -back black
        if (Get-ADUser -Identity $user) {
            Get-ADUser -Identity $user | Move-ADObject -TargetPath 'OU=Terminated Users,DC=COG,DC=COGGOV,DC=LOCAL'
            $curuser = Get-ADUser -Identity $user -Properties Description
            $curdesc = $curuser.Description
            Get-ADUser -Identity $user | Set-ADUser -Enabled $false -Description "Disabled $year by script. $curdesc"
        } else {
            Write-Host "Error. No user found in Active Directory." -Fore red -back black
        }
    }
    Default {
        Write-Host "Wrong Domain Entered. Skipping AD commands." -ForegroundColor Red -back black
    }
}



Switch ($domainnumber) {
    1 {
        # Get-mailbox searches for the mailbox and returns true if it exists
        if (Get-Mailbox -Identity "COG\$user") {
            # if the mailbox exists we'll hide it from the address lists
            Write-Host "Hiding from Address List." -Fore Yellow -back black
            Set-Mailbox -Identity "COG\$user" -HiddenFromAddressListsEnabled $true
        } else {
            Write-Host "No mailbox. Skipping Hide From Address List." -Fore Yellow -back black
        }
    }
    2 {
        # Get-mailbox searches for the mailbox and returns true if it exists
        if (Get-Mailbox -Identity "GPD\$user") {
            # if the mailbox exists we'll hide it from the address lists
            Write-Host "Hiding from Address List." -Fore Yellow -back black
            Set-Mailbox -Identity "GPD\$user" -HiddenFromAddressListsEnabled $true
        } else {
            Write-Host "No mailbox. Skipping Hide From Address List." -Fore Yellow -back black
        }
    }
    3 {
        # Get-mailbox searches for the mailbox and returns true if it exists
        if (Get-Mailbox -Identity "COG\$user") {
            # if the mailbox exists we'll hide it from the address lists
            Write-Host "Hiding from Address List." -Fore Yellow -back black
            Set-Mailbox -Identity "COG\$user" -HiddenFromAddressListsEnabled $true
        } else {
            Write-Host "No mailbox. Skipping Hide From Address List." -Fore Yellow -back black
        }
    }
    Default {
        Write-Host "Wrong Domain Entered. Skipping GAL commands." -ForegroundColor Red -back black
    }
}



Switch ($domainnumber) {
    1 {
        # Based on the user input earlier this will either copy the user directory or skip this portion
        Switch ($copyfiles)
        { 
                $true {
                    Write-host "Copying Files" -ForegroundColor Yellow -back black
                    robocopy "$cogshareroot$user" "${cogsharetermroot}TermUsrsScripted_$year\$user" /E /COPYALL /ETA /LOG:C:\Offboarding\OffboardFileTransferLog$user$year.txt
                    Write-host "Copy complete." -ForegroundColor Yellow -back black
                    Write-host "Checking if source and destination directories match contents." -ForegroundColor Yellow -back black
                    $fso = Get-ChildItem -Recurse -path "$cogshareroot$user" | Where-Object { -not $_.PSIsContainer }
                    $fsd = Get-ChildItem -Recurse -path "${cogsharetermroot}TermUsrsScripted_$year\$user" | Where-Object { -not $_.PSIsContainer }
                    if (Test-Path -Path "$cogshareroot$user") {
                        if ($fso) {
                            if (!(Compare-Object $fso $fsd)) {
                                        Write-host "Directories match, deleting files from $cogshareroot$user" -ForegroundColor Yellow -back black
                                        Remove-Item "$cogshareroot$user" -Recurse -Force
                            } else {
                                        Write-host "Directories do not match, the copy operation did not successfully transfer all files." -ForegroundColor Red -back black
                            }
                        } else {
                            Write-host "No files to copy from the user folder. Deleting files from $cogshareroot$user" -ForegroundColor Yellow -back black
                            Remove-Item "$cogshareroot$user" -Recurse -Force
                        }
                    } else {
                        Write-host "Source directory does not exist." -ForegroundColor Red -back black
                    }
                  } 
                $false {
                  } 
                Default {Write-Host "Skipping file transfer. Please do so by hand from $cogshareroot to \\cog-chfs\software$\netadmin\_TermEmp" -ForegroundColor Yellow -back black} 
        }
    }
    2 {
        # Based on the user input earlier this will either copy the user directory or skip this portion
        Switch ($copyfiles)
        { 
                $true {
                    Write-host "Copying Files" -ForegroundColor Yellow -back black
                    robocopy "$gpdshareroot$user" "${cogsharetermroot}TermUsrsScripted_$year\$user" /E /COPYALL /ETA /LOG:C:\Offboarding\OffboardFileTransferLog$user$year.txt
                    Write-host "Copy complete." -ForegroundColor Yellow -back black
                    Write-host "Checking if source and destination directories match contents." -ForegroundColor Yellow -back black
                    $fso = Get-ChildItem -Recurse -path "$gpdshareroot$user"
                    $fsd = Get-ChildItem -Recurse -path "${cogsharetermroot}TermUsrsScripted_$year\$user"
                    if (Test-Path -Path "$gpdshareroot$user") {
                        if ($fso) {
                            if (!(Compare-Object $fso $fsd)) {
                                        Write-host "Directories match, deleting files from $gpdshareroot$user" -ForegroundColor Yellow -back black
                                        Remove-Item "$gpdshareroot$user" -Recurse -Force
                            } else {
                                        Write-host "Directories do not match, the copy operation did not successfully transfer all files." -ForegroundColor Red -back black
                            }
                        } else {
                            Write-host "No files to copy from the user folder, deleting folder." -ForegroundColor Red -back black
                            Remove-Item "$gpdshareroot$user" -Recurse -Force
                        }
                    } else {
                        Write-host "Source directory does not exist." -ForegroundColor Red -back black
                    }
                    
                    
                  } 
                $false {
                  } 
                Default {Write-Host "Skipping file transfer. Please do so by hand from $gpdshareroot to \\cog-chfs\software$\netadmin\_TermEmp" -ForegroundColor Yellow -back black} 
        }
    }
    3 {
        # Based on the user input earlier this will either copy the user directory or skip this portion
        Switch ($copyfiles)
        { 
                $true {
                    Write-host "Copying Files" -ForegroundColor Yellow -back black
                    robocopy "$nmlsshareroot$user" "${cogsharetermroot}TermUsrsScripted_$year\$user" /E /COPYALL /ETA /LOG:C:\Offboarding\OffboardFileTransferLog$user$year.txt
                    Write-host "Copy complete." -ForegroundColor Yellow -back black
                    Write-host "Checking if source and destination directories match contents." -ForegroundColor Yellow -back black
                    $fso = Get-ChildItem -Recurse -path "$nmlsshareroot$user" | Where-Object { -not $_.PSIsContainer }
                    $fsd = Get-ChildItem -Recurse -path "${cogsharetermroot}TermUsrsScripted_$year\$user" | Where-Object { -not $_.PSIsContainer }
                    if (Test-Path -Path "$nmlsshareroot$user") {
                        if ($fso) {
                            if (!(Compare-Object $fso $fsd)) {
                                        Write-host "Directories match, deleting files from $nmlsshareroot$user" -ForegroundColor Yellow -back black
                                        Remove-Item "$nmlsshareroot$user" -Recurse -Force
                            } else {
                                        Write-host "Directories do not match, the copy operation did not successfully transfer all files." -ForegroundColor Red -back black
                            }
                        } else {
                            Write-host "No files to copy from the user folder. Deleting files from $nmlsshareroot$user" -ForegroundColor Yellow -back black
                            Remove-Item "$nmlsshareroot$user" -Recurse -Force
                        }
                    } else {
                        Write-host "Source directory does not exist." -ForegroundColor Red -back black
                    }
                  } 
                $false {
                  } 
                Default {Write-Host "Skipping file transfer. Please do so by hand from $nmlsshareroot to \\cog-chfs\software$\netadmin\_TermEmp" -ForegroundColor Yellow -back black} 
        }
    }
    Default {
        Write-Host "Wrong Domain Entered. Skipping directory move commands." -ForegroundColor Red -back black
    }
}



Switch ($domainnumber) {
    1 {
        # If this user has a mail contact it will be removed
        Write-Host "Checking if mail contact exists. If it doesn't an error might be thrown here." -Fore Yellow -back black
        if (Get-MailContact -Filter "Alias -like '*${user}*'") {
            Write-Host "Removing mail contact." -Fore Yellow -back black
            Get-MailContact -Filter "Alias -like '*${user}*'" | Remove-MailContact -Confirm:$false
        } else {
            Write-Host "No mail contact. Skipping Remove Mail Contact." -Fore Yellow -back black
        }
    }
    2 {
        # If this user has a mail contact it will be removed
        Write-Host "Checking if mail contact exists. If it doesn't an error might be thrown here." -Fore Yellow -back black
        if (Get-MailContact -DomainController $gpdDC -Filter "Alias -like '*${user}*'") {
            Write-Host "Removing mail contact." -Fore Yellow -back black
            Get-MailContact -DomainController $gpdDC -Filter "Alias -like '*${user}*'" | Remove-MailContact -DomainController $gpdDC -Confirm:$false
        } else {
            Write-Host "No mail contact. Skipping Remove Mail Contact." -Fore Yellow -back black
        }
    }
    3 {
        # If this user has a mail contact it will be removed
        Write-Host "Checking if mail contact exists. If it doesn't an error might be thrown here." -Fore Yellow -back black
        if (Get-MailContact -Filter "Alias -like '*${user}*'") {
            Write-Host "Removing mail contact." -Fore Yellow -back black
            Get-MailContact -Filter "Alias -like '*${user}*'" | Remove-MailContact -Confirm:$false
        } else {
            Write-Host "No mail contact. Skipping Remove Mail Contact." -Fore Yellow -back black
        }
    }
    Default {
        Write-Host "Wrong Domain Entered. Skipping mail contact remove commands." -ForegroundColor Red -back black
    }
}



Switch ($domainnumber) {
    1 {
        # If the mailbox exists then start the mailbox export request.
        if (Get-Mailbox -Identity $user) {
            Write-host "Copying Mailbox." -ForegroundColor Yellow -back black
            New-MailboxExportRequest -Mailbox $user -FilePath "\\COG-EMTMail1\m$\pstexports\$user.pst" -BadItemLimit 1000 -LargeItemLimit 1000 -Confirm:$false -AcceptLargeDataLoss
            $exportrequest = Get-MailboxExportRequest | ? {$_.FilePath -like "*$user*"}
            $mailboxsize = Get-MailboxStatistics $user | Select TotalItemSize
            $mailboxcount = Get-MailboxStatistics $user | Select ItemCount
            Write-host "Mailbox size is $mailboxsize with $mailboxcount items." -ForegroundColor Yellow -back black
            Write-host "Waiting for request to finish." -ForegroundColor Yellow -back black
    
            # Wait for the export request's status to be completed.
            while (!($exportrequest.Status -eq "Completed"))
            {
                Write-host "." -ForegroundColor Yellow -back black -NoNewline
                Start-Sleep 5

                # Update the variable to the latest status. Without this, the variable would never read as completed.
                $exportrequest = Get-MailboxExportRequest | ? {$_.FilePath -like "*$user*"}
            }

            # Remove the mailboxexportrequest once it is complete.
            Write-host "Removing MailboxExportRequest and copying item to destination user folder." -ForegroundColor Yellow -back black
            $exportrequest | Remove-MailboxExportRequest -Confirm:$false
    
            # Check if the user has a folder in the _TermEmp directory. If their folder was copied earlier, they will
            # if you selected N at the prompt to copy their user folder, they won't have this directory so it needs to be
            # created before we can copy the PST over
            if(!(Test-Path -PathType Container -Path "${cogsharetermroot}TermUsrsScripted_$year\$user")) {
                Write-host "Destination for PST copy does not exist, creating user folder in _TermEmp" -ForegroundColor Yellow -back black
                New-Item -ItemType Directory -Path "\\cog-chfs\software$\netadmin\_TermEmp\TermUsrsScripted_$year\$user" -Force
            }

            # Copy the PST over
            Copy-Item -Path "\\COG-EMTMail1\m$\pstexports\$user.pst" -Destination "${cogsharetermroot}TermUsrsScripted_$year\$user\$user.pst"
    
            # Compare the PSTs and make sure it successfully copied. If it has, delete the original
            $destinationpst = Get-Item -Path "${cogsharetermroot}TermUsrsScripted_$year\$user\$user.pst"
            $originpst = Get-Item -Path "\\COG-EMTMail1\m$\pstexports\$user.pst"
            if (Compare-Object -ReferenceObject $destinationpst -DifferenceObject $originpst) {
                Write-host "Copy successful, removing PST from export directory." -ForegroundColor Yellow -back black
                Remove-Item "\\COG-EMTMail1\m$\pstexports\$user.pst"
            } else {
                Write-host "Copy failed, destination PST does not match source PST." -ForegroundColor Red -BackgroundColor black
            }
        } else {
            Write-Host "No mailbox. Skipping mailbox export." -Fore Yellow -back black
        }
    }
    2 {
        # If the mailbox exists then start the mailbox export request.
        if (Get-Mailbox -DomainController $gpdDC -Identity $user) {
            Write-host "Copying Mailbox." -ForegroundColor Yellow -back black
            New-MailboxExportRequest -DomainController $gpdDC -Mailbox $user -FilePath "\\COG-EMTMail1\m$\pstexports\$user.pst" -BadItemLimit 1000 -LargeItemLimit 1000 -Confirm:$false -AcceptLargeDataLoss
            $exportrequest = Get-MailboxExportRequest | ? {$_.FilePath -like "*$user*"}
            $mailboxsize = Get-MailboxStatistics -DomainController $gpdDC $user | Select TotalItemSize
            $mailboxcount = Get-MailboxStatistics -DomainController $gpdDC $user | Select ItemCount
            Write-host "Mailbox size is $mailboxsize with $mailboxcount items." -ForegroundColor Yellow -back black
            Write-host "Waiting for request to finish." -ForegroundColor Yellow -back black
    
            # Wait for the export request's status to be completed.
            while (!($exportrequest.Status -eq "Completed"))
            {
                Write-host "." -ForegroundColor Yellow -back black -NoNewline
                Start-Sleep 5

                # Update the variable to the latest status. Without this, the variable would never read as completed.
                $exportrequest = Get-MailboxExportRequest | ? {$_.FilePath -like "*$user*"}
            }

            # Remove the mailboxexportrequest once it is complete.
            Write-host "Removing MailboxExportRequest and copying item to destination user folder." -ForegroundColor Yellow -back black
            #$exportrequest = Get-MailboxExportRequest -DomainController $gpdDC | ? {$_.FilePath -like "*$user*"}
            #$exportrequest | Remove-MailboxExportRequest -DomainController $gpdDC -Confirm:$false
            #$exportrequest = Get-MailboxExportRequest | ? {$_.FilePath -like "*$user*"}
            $exportrequest | Remove-MailboxExportRequest -Confirm:$false
    
            # Check if the user has a folder in the _TermEmp directory. If their folder was copied earlier, they will
            # if you selected N at the prompt to copy their user folder, they won't have this directory so it needs to be
            # created before we can copy the PST over
            if(!(Test-Path -PathType Container -Path "${cogsharetermroot}TermUsrsScripted_$year\$user")) {
                Write-host "Destination for PST copy does not exist, creating user folder in _TermEmp" -ForegroundColor Yellow -back black
                New-Item -ItemType Directory -Path "\\cog-chfs\software$\netadmin\_TermEmp\TermUsrsScripted_$year\$user" -Force
            }

            # Copy the PST over
            Copy-Item -Path "\\COG-EMTMail1\m$\pstexports\$user.pst" -Destination "${cogsharetermroot}TermUsrsScripted_$year\$user\$user.pst"
    
            # Compare the PSTs and make sure it successfully copied. If it has, delete the original
            $destinationpst = Get-Item -Path "${cogsharetermroot}TermUsrsScripted_$year\$user\$user.pst"
            $originpst = Get-Item -Path "\\COG-EMTMail1\m$\pstexports\$user.pst"
            if (Compare-Object -ReferenceObject $destinationpst -DifferenceObject $originpst) {
                Write-host "Copy successful, removing PST from export directory." -ForegroundColor Yellow -back black
                Remove-Item "\\COG-EMTMail1\m$\pstexports\$user.pst"
            } else {
                Write-host "Copy failed, destination PST does not match source PST." -ForegroundColor Red -BackgroundColor black
            }
        } else {
            Write-Host "No mailbox. Skipping mailbox export." -Fore Yellow -back black
        }
    }
    3 {
        # If the mailbox exists then start the mailbox export request.
        if (Get-Mailbox -Identity $user) {
            Write-host "Copying Mailbox." -ForegroundColor Yellow -back black
            New-MailboxExportRequest -Mailbox $user -FilePath "\\COG-EMTMail1\m$\pstexports\$user.pst" -BadItemLimit 1000 -LargeItemLimit 1000 -Confirm:$false -AcceptLargeDataLoss
            $exportrequest = Get-MailboxExportRequest | ? {$_.FilePath -like "*$user*"}
            $mailboxsize = Get-MailboxStatistics $user | Select TotalItemSize
            $mailboxcount = Get-MailboxStatistics $user | Select ItemCount
            Write-host "Mailbox size is $mailboxsize with $mailboxcount items." -ForegroundColor Yellow -back black
            Write-host "Waiting for request to finish." -ForegroundColor Yellow -back black
    
            # Wait for the export request's status to be completed.
            while (!($exportrequest.Status -eq "Completed"))
            {
                Write-host "." -ForegroundColor Yellow -back black -NoNewline
                Start-Sleep 5

                # Update the variable to the latest status. Without this, the variable would never read as completed.
                $exportrequest = Get-MailboxExportRequest | ? {$_.FilePath -like "*$user*"}
            }

            # Remove the mailboxexportrequest once it is complete.
            Write-host "Removing MailboxExportRequest and copying item to destination user folder." -ForegroundColor Yellow -back black
            $exportrequest | Remove-MailboxExportRequest -Confirm:$false
    
            # Check if the user has a folder in the _TermEmp directory. If their folder was copied earlier, they will
            # if you selected N at the prompt to copy their user folder, they won't have this directory so it needs to be
            # created before we can copy the PST over
            if(!(Test-Path -PathType Container -Path "${cogsharetermroot}TermUsrsScripted_$year\$user")) {
                Write-host "Destination for PST copy does not exist, creating user folder in _TermEmp" -ForegroundColor Yellow -back black
                New-Item -ItemType Directory -Path "\\cog-chfs\software$\netadmin\_TermEmp\TermUsrsScripted_$year\$user" -Force
            }

            # Copy the PST over
            Copy-Item -Path "\\COG-EMTMail1\m$\pstexports\$user.pst" -Destination "${cogsharetermroot}TermUsrsScripted_$year\$user\$user.pst"
    
            # Compare the PSTs and make sure it successfully copied. If it has, delete the original
            $destinationpst = Get-Item -Path "${cogsharetermroot}TermUsrsScripted_$year\$user\$user.pst"
            $originpst = Get-Item -Path "\\COG-EMTMail1\m$\pstexports\$user.pst"
            if (Compare-Object -ReferenceObject $destinationpst -DifferenceObject $originpst) {
                Write-host "Copy successful, removing PST from export directory." -ForegroundColor Yellow -back black
                Remove-Item "\\COG-EMTMail1\m$\pstexports\$user.pst"
            } else {
                Write-host "Copy failed, destination PST does not match source PST." -ForegroundColor Red -BackgroundColor black
            }
        } else {
            Write-Host "No mailbox. Skipping mailbox export." -Fore Yellow -back black
        }
    }
    Default {
        Write-Host "Wrong Domain Entered. Skipping mail contact remove commands." -ForegroundColor Red -back black
    }
}




Write-Host "Script complete." -ForegroundColor Green -BackgroundColor Black
Write-Host "Press enter to exit." -ForegroundColor Green -BackgroundColor Black

Stop-Transcript

Read-Host