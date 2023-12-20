# FileShare
E2E Encrypted Filesharing System

Built a filesharing system similar to dropbox/Google Docs that supports multiple users and file directories, file invites and sharing, and deletion/addition in constant time. This project was done in Golang with a partner for UC Berkeley's Computer Security CS161 class. 
The main features we implemented were: 

  1. Authenticate with a username and password;
  2. Save files to the server;
  3. Load saved files from the server;
  4. Overwrite saved files on the server;
  5. Append to saved files on the server;
  6. Share saved files with other users; and
  7. Revoke access to previously shared files.

to build a secure client applciation on a compromised server in Go. This meant that all the information stored on the server had to be HMACed and decrypted to serve to the user including filenames, usernames and passcodes, invites, and file contents. 

See the Design Here:
https://docs.google.com/presentation/d/1_hBlsUWEr97PvIaEcPQUFnoam4lH7O32G6eGF1YVuY8/edit?usp=sharing 
