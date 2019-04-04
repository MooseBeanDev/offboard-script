# offboard-script
Disables a user, moves them to a terminated users OU, backs up their files, exports their mailbox, and deletes their shared folder.

This script automates the offboarding procedure.

## User Input Required:

Offboarded user last name (searches AD to display their account name so you don't have to look it up)

AD Account/Username from the above search

Select Domain by typing (1) for XXX or (2) for XXX (Intended for multi-domain forests. Edit the script and remove this if you only need to query one domain.)

Yes or No confirmation to copy over the user's network share drive (it will give you its size. say no if the folder is too big.)

NOTE: THIS WILL DELETE THEIR SOURCE FOLDER FROM \\user$ but only if the directories match exactly after the copy.

## Script Workflow

Check if the active directory account exists. If so it will be moved to Terminated Users OU and disabled.

Check if the user's mailbox exists. If so, it will hide them from the Global Address List.

Check if a mail contact exists for the user. If so, it will be deleted.

Check if the user has a folder in \\user$ and copy it to \\_TermEmp\$user if so, will then delete the source folder

Check if the user has a mailbox. If so, it will export the PST, copy that PST to their _Termination folder, and clean itself up
