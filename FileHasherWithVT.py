'''
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

*For obvious reasons, like preventing abuse related to my own personal VT API key, I've ommitted mine
from this script. You should place your own VT API key in it's place.*

Example VT output: “The requested resource is not among the finished, queued or pending scans” >> means that the file's hash or file 
was never previously submitted to VT. 

Future Plans:

Command-line arg mode:
    1) Adjust script to allow command-line processing for scrictly file hashing or user guided.

Final Notes: 

This script just like many other on my GitHub page are tools that I delevoped as projects in response to my 
cybersecurity engineering coursework at the University of Arizona. With that in mind, much of the functionality 
isn't exactly novel or groundbreaking, but simply a method for me to apply my skills and have fun with python.

'''

import os                           # Standard Operating System Methods
import time
import sys
import json
import hashlib
import argparse                     # Command Line Argument Parsing

from prettytable import PrettyTable
from virus_total_apis import PublicApi as VirusTotalPublicApi

''' Globals '''

versionNumber = 'v1.2'

# The below API Key is my own PRIVATE VIRUSTOTAL API KEY! Do not include in GitHub Push!!! 
API_KEY = ''

# creating VT object
vt = VirusTotalPublicApi(API_KEY)

''' START OF FUNCTIONS '''

def inputValidation(userInput, validateWhat):
    
    ''' Input Validation for Directories '''
    if validateWhat == "Directory":
        # set user prompt count
        promptCount = 1    
        
        while promptCount <= 5: 
            # input validation
            if not os.path.isdir(userInput):
                # only allow 5 trys for a dir
                if promptCount == 5:
                    print('\n\nERROR: No Valid Directory Provided. Exiting...\n\n')    
                    sys.exit() 
                else:
                    promptCount += 1
                    userInput = input('Please Provide a Target Directory of Files to Hash:  ')
            else:
                # it's a valid dir so exit the loop
                break
            
        # return in the event that it is different than what was passed 
        return userInput
            
    ''' Input Validation for Virus Total Submission '''    
    if validateWhat == "Virus Total":
        # set user prompt count
        promptCount = 1    
        
        while promptCount <= 2: 
            # input validation
            if not (userInput == "n" or userInput == "y"):
                # only allow 5 trys for a dir
                if promptCount == 2:
                    print('\n\nERROR: Invalid Choice. Exiting...\n\n')    
                    sys.exit() 
                else:
                    promptCount += 1
                    # standardizing input to all lower case
                    userInput = input('Submit all File Hashes to Virus Total? (Y/N)    ').lower()
            else:
                # it's a valid dir so exit the loop
                break
            
        # return in the event that it is different than what was passed 
        return userInput        
            
    if validateWhat == "Output File":
        # set user prompt count
        promptCount = 1    
        
        while promptCount <= 2: 
            # input validation
            if not (userInput == "n" or userInput == "y"):
                # only allow 5 trys for a dir
                if promptCount == 2:
                    print('\n\nERROR: Invalid Choice. Exiting...\n\n')    
                    sys.exit() 
                else:
                    promptCount += 1
                    # standardizing input to all lower case
                    userInput = input('Save Virus Total Results to an output file? (Y/N)    ').lower()
            else:
                # it's a valid dir so exit the loop
                break  
            
        # return in the event that it is different than what was passed 
        return userInput        
            


def hashWithVT(userDirectory):
    
    # tracking the num of files submitted or not processed
    submittedCount = 0
    notSubmittedCount = 0
    notProcessedCount  = 0
    ProcessedCount = 0    
    
    # get the path of the current file
    currentFilePath = os.path.abspath(__file__)
    
    # get the path of the parent directory
    parentDirPath = os.path.dirname(currentFilePath)
    
    # construct the path to the TARGET directory
    targetDir = os.path.join(parentDirPath, userDirectory)
    
    # create a pretty table for file hashes 
    hashTable = PrettyTable(["File Name","Hash Type", "File Hash"]) 
    
    # walk the path from top to bottom
    for root, dirs, files in os.walk(targetDir): 
        
        print()
        print("="*56)
        print('Hashing ' +str(len(files))+ ' files from the '+ str(userProvidedDir), 'directory, please wait...')
        print("="*56)
        print()
        
        ''' File Hashing: process each file in the userProvidedDir '''
        for eachFile in files:
            # combining the root path w/ the file names
            path = os.path.join(root, eachFile)
                
            # storing the full path
            fullPath = os.path.abspath(path) 
            
            # don't want to submit this file & if I do I will exceed the API key limit for a 1 min period
            if eachFile != ".DS_Store":
                try:
                    # in order to hash the file we need to open it and read the binary data
                    with open(fullPath, 'rb') as fileToHash:                   
                        
                        #print("\nHashing File:",eachFile)
                        buffer = fileToHash.read()        
            
                        ''' Automatically create file hashes for common types & add to pretty table '''
                        fileHashMD5 = hashlib.md5(buffer).hexdigest()
                        hashTable.add_row([eachFile,"MD5",fileHashMD5])
                        
                        fileHashSHA1 = hashlib.sha1(buffer).hexdigest() 
                        hashTable.add_row([eachFile,"SHA-1",fileHashSHA1])
                        
                        fileHashSHA256 = hashlib.sha256(buffer).hexdigest() 
                        hashTable.add_row([eachFile,"SHA-256",fileHashSHA256]) 
                        
                        fileHashSHA512 = hashlib.sha512(buffer).hexdigest() 
                        hashTable.add_row([eachFile,"SHA-512",fileHashSHA512])   
                        
                        # increment count for successfully processed file
                        ProcessedCount += 1
            
                except:
                    # couldn't open file or some other error
                    notProcessedCount += 1
                    print("File could not be processed:",eachFile,"\n\n")
                    
        # formating & printing pretty table
        hashTable.align = 'l'
        print(hashTable.get_string(sortby="Hash Type"))     
        
        ''' Print Recap or Continuing '''
        
        if not virusTotalSubmission == 'y':                                       
            print("\n\nAll files have been processed. Printing Recap.\n")
            print("="*36)
            print("Number of hashes processed:      ",str(ProcessedCount))
            print("Number of hashes not processed:  ",str(notProcessedCount))
            print("="*36)
        else:
            ''' VT Submission: process each file for virus total submission '''          
            if virusTotalSubmission == 'y':
                # needed to bypass VT API rate limit for free accounts
                rateLimiterCount = 0
                
                for eachFile in files:
                    # combining the root path w/ the file names
                    path = os.path.join(root, eachFile)
                        
                    # storing the full path
                    fullPath = os.path.abspath(path) 
                    
                    # don't want to submit this file
                    if eachFile != ".DS_Store":
                        try:
                            # need to submit the MD5 file hash for each file
                            with open(fullPath, 'rb') as fileToHash:
        
                                buffer = fileToHash.read()        
                                fileHash = hashlib.md5(buffer).hexdigest()                    
                            
                                # submit each MD5 hash to VirusTotal for analysis
                                response =  vt.get_file_report(fileHash)
                                    
                                # print out the results in a json format
                                print()
                                print("="*30)
                                print("Printing Virus Total Results:") 
                                print("="*30)
                                print (json.dumps(response, sort_keys=False, indent=4))   
            
                                # tracking how many hashes were submitted successfully   
                                submittedCount += 1   
                                rateLimiterCount += 1 
                                
                                # checking fot output file or not
                                if virusOutputfile.lower() == 'y':
                                    ''' Saving JSON output to a file '''
                                    # convert response data to JSON string
                                    json_string = json.dumps(response, sort_keys=False, indent=4)
                                    
                                    # write formatted JSON string to file in append mode
                                    with open('VirusTotalOutput.txt', 'a') as file:
                                        # use f-string format in order to pass the variable name and string
                                        file.write("\n\n")
                                        file.write(f"Hashing File:   {eachFile}\n")
                                        file.write(f"File Hash (MD5): {fileHash}\n")
                                        file.write(json_string)
                                        
                                if submittedCount == 4:
                                    # VirusTotal has rate limits for its Free API usage
                                    time.sleep(60)
                                    # reset count for submitted
                                    rateLimiterCount = 0
                    
                        except:
                            # couldn't submit the fie hash
                            notSubmittedCount += 1
                            print("File hash could not be submitted:",eachFile,"\n\n")         
        
                ''' Print Recap '''  
                
                print("\n\nAll files have been processed. Printing Recap.\n")
                print("="*36)
                print("Number of hashes submitted:      ",str(submittedCount))
                print("Number of hashes not submitted:  ",str(notSubmittedCount))
                print("="*36)
                print("Number of hashes processed:      ",str(ProcessedCount))
                print("Number of hashes not processed:  ",str(notProcessedCount))    
                print("="*36)
        
                if virusOutputfile == 'y':
                    print()
                    print("Results saved to a file:          VirusTotalOutput.txt")    
                    
    ''' END OF FUNCTIONS '''

if __name__ == '__main__':
    
    print("="*32)
    print("Starting FileHasherWithVT",versionNumber)
    print("="*32)
    print()
    
    ''' Ask the user for target directory '''
    userProvidedDir = input('Please Provide a Target Directory of Files to Hash:  ')
    # call inputValidation function
    userProvidedDir = inputValidation(userProvidedDir, "Directory")
    
    
    ''' Ask user if they wish to submit to virus total '''
    virusTotalSubmission = input('Submit all File Hashes to Virus Total? (Y/N)         ').lower()
    # call inputValidation function
    virusTotalSubmission = inputValidation(virusTotalSubmission, "Virus Total")
    
    
    ''' Ask user if they wish to save the VT results to a file '''
    # checking fot VT submission
    if virusTotalSubmission == 'y':
        # asking user to save the default output file
        virusOutputfile = input('Save Virus Total Results to an output file? (Y/N)    ').lower()
        # call inputValidation function
        virusOutputfile = inputValidation(virusOutputfile, "Output File")
        
        if virusOutputfile.lower() == 'y':
            print()
            print('Output File Will be Saved as VirusTotalOutput.txt') 
    
    '''  Call the hash w/ VT function  '''
    hashWithVT(userProvidedDir)

    '''  All Done  '''
    print("\n\n")
    print('FileHasherWithVT',versionNumber,'Closing...\n')