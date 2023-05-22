# FileHasherWithVT

Title:             FileHasherWithVT
Verison:           1.2
Author:            NTGx86
Last Modified:     May 22 2023


Short Description: 

This script hashes files for common hash types & provides optional VirusTotal Submission. 
Common hashes include: MD5, SHA-1, SHA-256, SHA-512

Detailed Description: 

This program currently runs in one mode, but will soon support two modes. The first being an user prompt mode 
if no additional command line arguments are provided. The second mode will accept command-line args to 
accomodate hash generation for specific files or for entire directories of files. File hashes for both modes 
are displayed by using a pretty table. 


Virus Total (VT) Notes: 

For obvious reasons, like preventing abuse related to my own personal VT API key, I've ommitted mine
from this script. You should place your own VT API key in it's place

Example VT output: “The requested resource is not among the finished, queued or pending scans” >> means that the file's hash or file 
was never previously submitted to VT. 

Future Plans:

Command-line arg mode:
    1) Adjust script to allow command-line processing for scrictly file hashing or user guided.

Final Notes: 

This script just like many other on my GitHub page are tools that I delevoped as projects in response to my 
cybersecurity engineering coursework at the University of Arizona. With that in mind, much of the functionality 
isn't exactly novel or groundbreaking, but simply a method for me to apply my skills and have fun with python.