# FileShare
E2E Encrypted Filesharing System
Built a filesharing system similar to dropbox/Google Docs that supports multiple users and file directories, file invites and sharing, and deletion/addition in constant time. 
The main features we implemented were: 
  Authenticate with a username and password;
  Save files to the server;
  Load saved files from the server;
  Overwrite saved files on the server;
  Append to saved files on the server;
  Share saved files with other users; and
  Revoke access to previously shared files.
to build a secure client applciation on a compromised server in Go. This meant that all the information stored on the server had to be HMACed and decrypted to serve to the user including filenames, usernames and passcodes, invites, and file contents. 

See the Design Here:
https://docs.google.com/presentation/d/1_hBlsUWEr97PvIaEcPQUFnoam4lH7O32G6eGF1YVuY8/edit?usp=sharing 

Because this is the currently used project in CS161 I can only provide code upon request. 
