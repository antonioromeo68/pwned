# PWNED - ver 1.3 - 08/05/2021
# Author: Antonio Romeo - Cinquefrondi (RC)
# email: ar111@hotmail.com
# This software is free of charge for personal usage. Since it may use an online service (to check if a pwd has been "pwned")
# the number of queries to the service may be subject to policy/licensing. I am not affiliated nor sponsored nor associated in any way 
# with the provider of the service. You need to get the owner permission (https://haveibeenpwned.com) for any "extensive" usage.
# My suggestion, if you have lot of pwd to check, is to download the hacked pwd DB from the same site and use it locally.
# But anyway you are on your own.
# Notes: when checking the password online, the pwd itself is NOT sent to anybody... checks are done against HASHED passwords 
#        in a way to anonymize the pwd itself.
# Feel free to send me any bug/improvement request. I will try to respond to anyone.
# Added -z switch (only support single password so far...)

import hashlib
import requests
import os
import sys
import getopt
import time
import threading
import zipfile

PROGRAM_VERSION="1.3"
DEBUG_MODE = False
SSL_CHECK  = False

HASH_PREFIX_LENGHT  = 5
BASE_PWD_SEARCH_URL = 'https://api.pwnedpasswords.com/range/'

#type of expected inputs for the scrypt
IM_UNKNOWN_MODE     = 0
IM_SINGLE_PASSOWRD  = 1 #a single password provided in the command line - can be plain text or sha1 hash depending on OPERATION_MODE
IM_PASSWORD_FILE    = 2 #a file containing password (one per line)
IM_TEXT_FILE        = 3 #a text file containing words that will be extracted as password (with some filter explained in command line help)

#work with plain text or SHA1 passwords (-s flag)
OM_PLAIN            = 1 #all password are provided to the script as plain text ... input password may be logged or showed on screen beware where you use this...
OM_HASH             = 2 #all password are provided to the script as SHA1.... and also logged or written as such (i.e. no passwords present anywhere...)

#work with the web service or with local file
DB_UNKNOWN          = 0
DB_WEB              = 1
DB_LOCAL            = 2
DB_LOCAL_ZIP        = 3

INPUT_MODES     = [IM_SINGLE_PASSOWRD, IM_PASSWORD_FILE, IM_TEXT_FILE]
OPERATION_MODES = [OM_PLAIN, OM_HASH]
DATABASE_MODES  = [DB_WEB, DB_LOCAL, DB_LOCAL_ZIP]

ERR_NO_ERROR         = 0
ERR_WRONG_PARAMETERS = 1
ERR_OTHERS           = 2
ERR_OPMODE_UNKNOWN   = 3
ERR_NO_HASH_PASSWORD = 4

#Global statistics:
g_number_of_password_read = 0   #1 if from command 
g_pwned_passwords_found   = 0
g_safe_passwords_found    = 0
g_scanned_lines_in_db     = 0  #if local db option used
g_safe_passwords_invalid  = 0


#Constants for the -f implementation....
#lines starting with the below will be excluded
LINES_TO_EXCLUDE = ["http", "https", "***", "---", "___", "#", "//", "/*"] 
#following chars will be changed to spaces
SPLIT_CHARS      = [":", "/", "=", "\t"]
#words longer than 5 will be excluded
MIN_WORD_LENGTH=5

#A line_tocheck with ANY of the words in "excluding_list" will return TRUE (so to be excluded)
def lineToBeExcluded(line_tocheck, excluding_list):
    result=False

    for word_to_exclude in excluding_list:
        result = result or line_tocheck.startswith(word_to_exclude)
           
    return result

def wordToBeExcluded(word_tocheck, min_word_length):
    result = (len(word_tocheck) < min_word_length)
    return result

def getPasswordList(filename):
 #     def __init__(self, src_password, src_hash, found_filename, found_linenumber, ispwned=False):
    # with context manager assures us the
    # file will be closed when leaving the scope
    file = open(filename, 'r', errors='ignore')
    lines = file.readlines()
   
    cleaned_word_list = []
    file_line=0
    for l in lines:
        file_line=file_line+1
        remove_unwanted=l.strip()

        if not(lineToBeExcluded(remove_unwanted, LINES_TO_EXCLUDE)):
            for chartoremove in SPLIT_CHARS:
                remove_unwanted = remove_unwanted.replace(chartoremove, " ")
        
            newline=remove_unwanted.split(" ")
            #assert " " not in newline
            for word in newline:
                if not(wordToBeExcluded(word, MIN_WORD_LENGTH)):
                    the_hash = hashlib.sha1()
                    the_hash.update(str(word).strip().encode('utf-8'))
                    new_rec= password_record(word, the_hash.hexdigest().upper(), filename, file_line, False)
                    cleaned_word_list.append(new_rec)
        
    return cleaned_word_list


class password_record:
    def __init__(self, src_password, src_hash, found_filename, found_linenumber, ispwned=False):
        self.src_password = src_password    # instance variable unique to each instance
        self.src_hash = src_hash
        self.found_filename = found_filename
        self.found_linenumber = found_linenumber
        self.ispwned = ispwned

def printStats():
    print("---------------------------------------------------------------")
    print("Total number of passwords/hash read.......: " + str(g_number_of_password_read))
    print("Total number of passwords/hash pwned......: " + str(g_pwned_passwords_found))
    print("Total number of passwords/hash safe.......: " + str(g_safe_passwords_found))
    print("Total number of passwords/hash invalid....: " + str(g_safe_passwords_invalid))
    print("Total number of lines scanned in local db : " + str(g_scanned_lines_in_db))
    print("---------------------------------------------------------------")
    return 

def debugLog(string_variable):
    global DEBUG_MODE
    if DEBUG_MODE:
        print("DEBUG: " + string_variable)
    return
    
def readTextPasswordFromTextFile(l_cli_password_file, l_inputmode=OM_PLAIN):
    result = []
    file = open(l_cli_password_file, 'r', errors='ignore')
    lines = file.readlines()
    file_line=0
    if l_inputmode==OM_PLAIN:
        debugLog("readTextPasswordFromTextFile - Reading in plain text mode (i.e. expecting plain passwords)")
        for l in lines:
            the_word=l.strip()
            file_line=file_line+1
            if the_word != "":
                the_hash = hashlib.sha1()

                the_hash.update(the_word.encode('utf-8'))  
        
                rec = password_record(the_word, the_hash.hexdigest().upper(), l_cli_password_file, file_line, False )
  
                result.append(rec)
            else:
                debugLog("readTextPasswordFromTextFile(OM_PLAIN):Skipping empty line")
    else:
        debugLog("readTextPasswordFromTextFile - Reading in Sha1 mode (i.e. expecting sha1 digests of passwords)")
        for l in lines:
            the_hash=l.strip()
            file_line=file_line+1
            if the_hash != "":
                rec = password_record("unknown", the_hash, l_cli_password_file, file_line, False )
                result.append(rec)
            else:
                debugLog("readTextPasswordFromTextFile(OM_HASH):Skipping empty line")

    return result

def writeListOfRecords(l_outputfilename, l_list_of_records):
    for new_current_record in l_list_of_records:
        writeOneRecord(l_outputfilename, new_current_record)
    return

def writeOneRecord(l_outputfilename, l_myrecord):
    writeOnePassword(l_outputfilename, l_myrecord.found_filename, l_myrecord.src_password, l_myrecord.src_hash, l_myrecord.found_linenumber, l_myrecord.ispwned   )
    return


def writeOnePassword(l_outputfilename, found_filename, src_password, src_hash, found_linenumber, i_ispwned ):
    debugLog("writeOnePassword("+ l_outputfilename + ", " + found_filename + ","+  src_password + ", " + src_hash + ", " + str(found_linenumber) + "," + str(i_ispwned)+ ")")

    if (l_outputfilename != ""):
        line_output=found_filename + ", " + str(found_linenumber) + ","+  src_password + ", " + src_hash  + "," + str(i_ispwned) + "\n"
        l_outfile = open(l_outputfilename, 'a', newline='\n')
        
        l_outfile.writelines(line_output)
        l_outfile.close()
    else:
        debugLog("writeOnePassword: No filename provided.")

    return

# press any key to continue function
def pressAnyKey(theprompt="Press any key to continue...", failChars='qQ'):
    '''
    Displays a prompt to the user, then waits for the user to press a key.
    Accepts a string for prompt, and a string containing all characters for which it should return False.
    Returns False if the char pressed was in the failChars string, True otherwise.
    Exit on Ctrl + C'''
    exit_char_pressed=False
    from msvcrt import getch, kbhit
    print (theprompt)
    ch = getch()
    while kbhit():
        getch()
    if ch == '\x03':
        os._exit(1)
    else:
        exit_char_pressed = (str(ch) in failChars)
    return exit_char_pressed

def showHelpShort():
    print("-----------------------------------------------------------------------------------------------------------------------")
    print("Sample usage:")
    print("pwned -p password123 -o thisiswhativefound.txt")
    print("pwned -p B0399D2029F64D445BD131FFAA399A42D2F8E7DC -s -o thisiswhativefound.txt")
    print("pwned -f file_with_passwords.txt -o thisiswhativefound.txt")
    print("pwned -f file_with_passwords_insha1_format.txt -s -o thisiswhativefound.txt")
    print("pwned --help")

def showHelp():
    print("Usage: pwned [-p password_to_check]|[-f pwds_filename]|[-t text_filename] [-s] [-l sha1_pwned_pwd_file] -d secs| [-h]")
    print("       pwned [--password password_to_check]|[-password_file pwds_filename]|[-text_file text_filename] [--sha1_format] [--local_sha1_db sha1_pwned_pwd_file] --delay secs | [--help]")
    print("-----------------------------------------------------------------------------------------------------------------------")    
    print("\nCheck a password or a list of password against a DB of breaches maintained at https://haveibeenpwned.com/Passwords")
    print("By default uses api at: " + BASE_PWD_SEARCH_URL)
    print("Using the -l parameter you can check a local file downloadable from the site above")
    print("No clear passwords are transmitted on the network.")
    print("Each pasword is hashed with SHA1 hash function and 5 chars of the hash hex representaion are used to query the remote db")
    pressAnyKey()
    print("-----------------------------------------------------------------------------------------------------------------------")
    print("Sample usage:")
    print("pwned -p password123 -o thisiswhativefound.txt")
    print("pwned -p B0399D2029F64D445BD131FFAA399A42D2F8E7DC -s -o thisiswhativefound.txt")
    print("pwned -f file_with_passwords.txt -o thisiswhativefound.txt")
    print("pwned -f file_with_passwords_insha1_format.txt -s -o thisiswhativefound.txt")
    print("-----------------------------------------------------------------------------------------------------------------------")
    print(" -p password_to_check (--password)      - password to check")
    print(" -f pwds_filename     (--password_file) - read a text file containing a list of 1 passwords per line (ending in \\n)") 
    print("                                          Each line must contain a plain text password or a SHA1 hash (if -s is used")
    print(" -t text_filename     (--text_file)     - read a text file continaing words. The idea is to implement a pwd parser...") 
    print("                                          -t is NOT YET IMPLEMENTED, same as -f option so far") 
    print(" -s                   (--sha1_format)   - inputs (from command line or files) is expected to be a SHA1 hex string")
    print("                                         lines beginning with # are skipped  - NOT IMPLEMENTED YET") 
    print("                                         lines containing *** # are skipped  - NOT IMPLEMENTED YET")
    print("                                         lines containing ___ # are skipped  - NOT IMPLEMENTED YET")
    print("                                         lines containing http # are skipped - NOT IMPLEMENTED YET")
    print(" -l sha1_filename     (--local_sha1_db )- A local text file containing the list of SHA1 hex string passwords")
    print("                                          Tested with the list of SHA1 passwords obtained from:")
    print("                                          https://haveibeenpwned.com/Passwords")
    print(" -z zip_filename      (--zipped)        - if the text file defined with -l is contained in the zip_filename")
    print(" -d secs_number       (--delay)         - when using the web server (i.e. if -l NOT used) requests are delayed")
    print("                                          (throtthled) by secs_number seconds. Ignored with -l")
    print(" -h                   (--help)          - print this message... override all other parameters")
    print(" -o out_filename      (--output_file )  - Write all passwords and the search result in the file named out_filename.")
    print("                                          If -s is used no passwords will be in the file")
    print("-----------------------------------------------------------------------------------------------------------------------")
    print("Output file (if used) is a csv file containing:")
    print("       source_file_name, line_number_in_src_file, plain_text_pwd_if_available, Sha1-version_of_the_pwd, True|False")
    print("-----------------------------------------------------------------------------------------------------------------------")
    print("\n")
    return


def hashMeThis(l_password):
    the_hashed_pwd = hashlib.sha1()
    the_hashed_pwd.update(str(l_password).strip().encode('utf-8'))
    the_hashed_pwd_string = the_hashed_pwd.hexdigest().upper()
    return the_hashed_pwd_string

def checkSinglePassword(l_password, l_current_input_mode, l_current_db_mode, l_cli_local_db_file, l_cli_local_zip, l_cli_output_file):

    debugLog("checkSinglePassword(" + l_password + "," + str(l_current_input_mode) + "," + str(l_current_db_mode) + "," + l_cli_local_db_file + "," + l_cli_local_zip + ","+  l_cli_output_file + ")")

    password_in_text_format = ""
    password_in_hash_format = ""

    if (l_current_input_mode == OM_HASH):
        password_in_text_format = "no_pwd"
        password_in_hash_format = l_password
        if len(password_in_hash_format) != 40:
            print(password_in_hash_format + " does NOT look as a SHA1 format...proceding as it was plaintext instead...")
            
            password_in_text_format = l_password
            password_in_hash_format = hashMeThis(l_password)
    else:
        password_in_text_format = l_password
        password_in_hash_format = hashMeThis(l_password)
    
    is_pwned = False
    if (l_current_db_mode == DB_WEB):
        is_pwned=isHashPwnedRemote(password_in_hash_format)
    elif (l_current_db_mode == DB_LOCAL_ZIP):
        is_pwned=isHashPwnedLocalZip(password_in_hash_format, l_cli_local_db_file, l_cli_local_zip)
    else:
        is_pwned=isHashPwnedLocal(password_in_hash_format, l_cli_local_db_file)
    
    writeOnePassword(l_cli_output_file, "cli", password_in_text_format, password_in_hash_format, 0, is_pwned )
   
    return

def checkPlainPasswordFile(l_cli_password_file, l_current_db_mode, l_cli_local_db_file, l_cli_output_file, l_inputmode=OM_PLAIN, l_delay_secs=0):
    debugLog("checkPlainPasswordFile(" + l_cli_password_file + "," + str(l_current_db_mode) + "," +l_cli_local_db_file + "," + l_cli_output_file +","+ str(l_inputmode) + "," + str(l_delay_secs)+")")

    global g_number_of_password_read
    global g_pwned_passwords_found
    global g_safe_passwords_found
    
    list_to_check = []  
    list_to_check = readTextPasswordFromTextFile(l_cli_password_file, l_inputmode)
    g_number_of_password_read = len(list_to_check)
    if (l_current_db_mode == DB_WEB):
        for current in list_to_check:
            current.ispwned=isHashPwnedRemote(current.src_hash)
            writeOneRecord(l_cli_output_file, current)
            time.sleep(l_delay_secs)
            debugLog("Throttling requests by secs:" + str(l_delay_secs))
    else:
        #isHashListPwnedLocalMT(list_to_check, l_cli_local_db_file, l_cli_output_file, OM_PLAIN)
        #below  is the working version...
        isHashListPwnedLocal(list_to_check, l_cli_local_db_file, l_cli_output_file, OM_PLAIN)
    return 

def checkTextFile(l_word_list, l_current_db_mode, l_cli_local_db_file, l_cli_output_file, l_delay_secs):
    debugLog("checkTextFile(l_word_list, " + str(l_current_db_mode) + "," + l_cli_local_db_file + "," + l_cli_output_file + ")")
    global g_number_of_password_read
    global g_pwned_passwords_found
    global g_safe_passwords_found
    
    list_to_check = l_word_list
    g_number_of_password_read = len(list_to_check)
    if (l_current_db_mode == DB_WEB):
        for current in list_to_check:
            current.ispwned=isHashPwnedRemote(current.src_hash)
            writeOneRecord(l_cli_output_file, current)
            time.sleep(l_delay_secs)
            debugLog("Throttling requests by secs:" + str(l_delay_secs))
    else:
        isHashListPwnedLocal(list_to_check, l_cli_local_db_file, l_cli_output_file, OM_PLAIN)
    return 

#added on 2021/12/27 to read from a zipped file....
def isHashPwnedLocalZip(l_hash, l_local_db_file, l_local_zip_file):
    debugLog("isHashPwnedLocalZip(" + l_hash + "," + l_local_db_file + ", " + l_local_zip_file + ")")
    result= False
    line_number=0
    global g_number_of_password_read
    global g_pwned_passwords_found
    global g_safe_passwords_found
    global g_scanned_lines_in_db
    last_digit = 0


    with zipfile.ZipFile(l_local_zip_file) as z:
        with z.open(l_local_db_file) as f:
            debugLog("isHashPwnedLocalZip-zip file is now open...:" + l_local_zip_file + ")")
            for the_line in f:
                line_number = line_number + 1
                if (l_hash.encode() in the_line):
                    g_number_of_password_read = 1
                    g_pwned_passwords_found   = 1
                    g_safe_passwords_found    = g_number_of_password_read - g_pwned_passwords_found
                    g_scanned_lines_in_db     = line_number 
                    result=True
                    print(l_hash + " FOUND on line " + str(line_number) + " of file " + l_local_db_file)
                    debugLog("isHashPwnedLocalZip result=" + str(result));
                    return result
                if (line_number % 100000) == 0:
                    last_digit = (last_digit+1) % 10
                    print(str(last_digit), end='', flush= True)
        
    g_number_of_password_read = 1
    g_pwned_passwords_found   = 0
    g_safe_passwords_found    = g_number_of_password_read - g_pwned_passwords_found
    g_scanned_lines_in_db     = line_number                 
    return result


def isHashPwnedLocal(l_hash, l_local_db_file):
    debugLog("isHashPwnedLocal(" + l_hash + "," + l_local_db_file + ")")
    result= False
    line_number=0
    global g_number_of_password_read
    global g_pwned_passwords_found
    global g_safe_passwords_found
    global g_scanned_lines_in_db
    last_digit = 0

    with open(l_local_db_file, 'r') as read_obj:
        for the_line in read_obj:
            line_number = line_number + 1
            if (l_hash in the_line):
                g_number_of_password_read = 1
                g_pwned_passwords_found   = 1
                g_safe_passwords_found    = g_number_of_password_read - g_pwned_passwords_found
                g_scanned_lines_in_db     = line_number 
                result=True
                print(l_hash + " FOUND on line " + str(line_number) + " of file " + l_local_db_file)
                return result

            if (line_number % 100000) == 0:
                last_digit = (last_digit+1) % 10
                print(str(last_digit), end='', flush= True)
                    
    g_number_of_password_read = 1
    g_pwned_passwords_found   = 0
    g_safe_passwords_found    = g_number_of_password_read - g_pwned_passwords_found
    g_scanned_lines_in_db     = line_number                 
    return result


def isHashListPwnedLocal(list_records, l_local_db_file, l_outputfilename, l_input_mode):
    debugLog("isHashListPwnedLocal(" + "list_records" + "," + l_local_db_file + "," + l_outputfilename + "," + str(l_input_mode) + ")")
    result= False #True if at least one password is found
    line_number=0
    last_digit=0
    total_records = len(list_records)
    true_records  = 0
    global g_number_of_password_read
    global g_pwned_passwords_found
    global g_safe_passwords_found
    global g_scanned_lines_in_db

    with open(l_local_db_file, 'r') as read_obj:
        for the_line in read_obj:
            line_number = line_number + 1
            for current_record in list_records:
                if (true_records < total_records):
                    if current_record.ispwned==False:
                        if (current_record.src_hash in the_line):
                            result=result or True
                            true_records = true_records + 1
                            current_record.ispwned = True
                            print("\n" + current_record.found_filename + "(" + str(current_record.found_linenumber) + ") -" + \
                                current_record.src_password + " -" + current_record.src_hash + " FOUND on line " + str(line_number) + \
                                " of file " + l_local_db_file + " - " + str(total_records-true_records) + " pwds to check...")
                else:
                    debugLog("isHashListPwnedLocal: exit and return... no more passwords to check. Total scanned lines: " + str(line_number))
                    writeListOfRecords(l_outputfilename, list_records)
                    g_number_of_password_read = total_records
                    g_pwned_passwords_found   = true_records
                    g_safe_passwords_found    = g_number_of_password_read - g_pwned_passwords_found
                    g_scanned_lines_in_db     = line_number #if local db option used
                    return
            if (line_number % 100000) == 0:
                last_digit = (last_digit+1) % 10
                print(str(last_digit), end='', flush= True)
        print("isHashListPwnedLocal - All passwords checked. Total scanned lines: " + str(line_number))
    writeListOfRecords(l_outputfilename, list_records)
    g_number_of_password_read = total_records
    g_pwned_passwords_found   = true_records
    g_safe_passwords_found    = g_number_of_password_read - g_pwned_passwords_found
    g_scanned_lines_in_db     = line_number #if local db option used
    return result

def checkListAgainstLineMT(list_records, l_line, thread_name):
    debugLog("checkListAgainstLineMT(" + "list_records" + "," + l_line+ "," + thread_name)
    number_of_true_records_found = 0
    global g_number_of_password_read
    global g_pwned_passwords_found
    global g_safe_passwords_found
    global g_scanned_lines_in_db
    for current_record in list_records:
        if current_record.ispwned==False:
            if (current_record.src_hash in l_line):
                #result=result or True
                number_of_true_records_found = number_of_true_records_found + 1
                current_record.ispwned = True
                print("\n" + thread_name + ": " + current_record.found_filename + "(" + str(current_record.found_linenumber) + ") -" + \
                    current_record.src_password + " -" + current_record.src_hash + " FOUND")
    
    return number_of_true_records_found

#Same as before but multi-threaded
def isHashListPwnedLocalMT(list_records, l_local_db_file, l_outputfilename, l_input_mode):
    debugLog("isHashListPwnedLocalMT(" + "list_records" + "," + l_local_db_file + "," + l_outputfilename + "," + str(l_input_mode) + ")")
    result= False #True if at least one password is found
    line_number=0
    last_digit=0
    total_records = len(list_records)
    true_records  = 0
    global g_number_of_password_read
    global g_pwned_passwords_found
    global g_safe_passwords_found
    global g_scanned_lines_in_db
    list_of_threads = []

    with open(l_local_db_file, 'r') as read_obj:
        for the_line in read_obj:
            line_number = line_number + 1
            #here I would like to spin a thread and move on...
            t = threading.Thread(target=checkListAgainstLineMT, args=(list_records, the_line, str(line_number)))
            t.start()
            list_of_threads.append(t)

            if (line_number % 100000) == 0:
                last_digit = (last_digit+1) % 10
                print(str(last_digit), end='', flush= True)

        for ttt in list_of_threads:
            ret = ttt.join()

        print("isHashListPwnedLocalMT - All passwords checked. Total scanned lines: " + str(line_number))
    
    writeListOfRecords(l_outputfilename, list_records)
    g_number_of_password_read = total_records
    g_pwned_passwords_found   = true_records
    g_safe_passwords_found    = g_number_of_password_read - g_pwned_passwords_found
    g_scanned_lines_in_db     = line_number #if local db option used
    return result

def isHashPwnedRemote(l_hash):
    debugLog("isHashPwnedRemote(" + l_hash + ")")
    result = False
    the_hashed_prefix = l_hash[0:(HASH_PREFIX_LENGHT)]
    the_hashed_suffix = l_hash[HASH_PREFIX_LENGHT:len(l_hash)]
    global g_pwned_passwords_found
    global g_number_of_password_read
    global g_safe_passwords_found
    global g_safe_passwords_invalid

    final_url = BASE_PWD_SEARCH_URL + the_hashed_prefix

    #WARNING_ verify=false added only on this local copy to avoid checking ssl certificate
    response = requests.get(final_url, verify=SSL_CHECK)

    if response.status_code == 200:
        print('Web service returned success status 200')
        #debugLog(response.text + "\n")
        if (the_hashed_suffix in response.text):
            print(l_hash + " FOUND! This password is PWNED")
            result = True
            g_pwned_passwords_found    = g_pwned_passwords_found + 1
        else:
            print(l_hash + " NOT FOUND! This password is SAFE")
            result = False
            g_safe_passwords_found    = g_safe_passwords_found + 1 
    elif response.status_code == 404:
        print('ERROR 404 - Page not Found.')
        g_safe_passwords_invalid = g_safe_passwords_invalid+1
    elif response.status_code == 429:
        print('ERROR 429 - rate limit exceeded. No Retry')
        g_safe_passwords_invalid = g_safe_passwords_invalid+1
    elif response.status_code == 400:
        print('ERROR 400 - The hash prefix was not valid hexadecimal')
        g_safe_passwords_invalid = g_safe_passwords_invalid+1
    else:
        print('ERROR Unknown: ' + str(response.status_code) + ' ' + response.text)
    
    return result



def isPasswordPwned(password_to_check):
    result = False
    the_hashed_pwd = hashlib.sha1()
    the_hashed_pwd.update(str(password_to_check).strip().encode('utf-8'))
    the_hashed_pwd_string = the_hashed_pwd.hexdigest().upper()

    the_hashed_prefix = the_hashed_pwd_string[0:(HASH_PREFIX_LENGHT)]
    the_hashed_suffix = the_hashed_pwd_string[HASH_PREFIX_LENGHT:len(the_hashed_pwd_string)]

    final_url = BASE_PWD_SEARCH_URL + the_hashed_prefix

    response = requests.get(final_url)

    if response.status_code == 200:
        print('You got the success!')
        print(response.text)
        if (the_hashed_suffix in response.text):
            print("Password ***" + password_to_check + "*** with hash " + the_hashed_pwd_string + " FOUND! Is PWNED")
            result = True
    elif response.status_code == 404:
        print('Page not Found.')
    elif response.status_code == 404:
        print('Rate limit exceeded.')
    else:
        print('Unknown Error: ' + str(response.status_code) + ' ' + response.message)
    
    return result


#*********************************************
#          MAIN is HERE
#*********************************************
debugLog('This program is now in DEBUG mode. To change put DEBUG_MODE = False at the beginning of the file.')

#Global operation modes and variables - by default the WEB service is used and input assumed in PLAIN TEXT mode
current_operation_mode  = IM_UNKNOWN_MODE
cli_password       = ""
cli_password_file  = ""
cli_text_file      = ""

cli_input_mode = OM_PLAIN

cli_db_mode    = DB_WEB
cli_local_db_file  = ""
cli_local_zip      = ""

cli_output_file    = ""
cli_delay_secs     = 0
# Remove 1st argument from the list of command line arguments
argumentList = sys.argv[1:]
# Options
options = "p:f:t:l:o:d:s:z:h"
# Long options
long_options = ["password", "password_file", "text_file", "local_sha1_file", "output_file", "delay", "sha1_format","zipped", "help"]

try:
    debugLog("Parsing command line arguments....\n" + str(argumentList))
    # Parsing argument
    arguments, values = getopt.getopt(argumentList, options, long_options)
     
    # checking each argument
    for currentArgument, currentValue in arguments:
        if currentArgument in ("-p", "--password"):   
            debugLog("-p " + currentValue + " found")
            if current_operation_mode == IM_TEXT_FILE:
                debugLog("-p " + currentValue + " found - Ignoring due to -t parameter found first....")
            elif current_operation_mode == IM_PASSWORD_FILE:
                debugLog("-p " + currentValue + " found - Ignoring due to -f parameter found first....")
            else:
                cli_password   = currentValue
                current_operation_mode = IM_SINGLE_PASSOWRD

        elif currentArgument in ("-f", "--password_file"):
            debugLog("-f " + currentValue + " found")
            if current_operation_mode == IM_SINGLE_PASSOWRD:
                debugLog("-f " + currentValue + " found - Ignoring due to -p parameter found first....")
            elif current_operation_mode == IM_PASSWORD_FILE:
                debugLog("-f " + currentValue + " found - Ignoring due to -t parameter found first....")
            else:
                cli_password           = ""
                current_operation_mode = IM_PASSWORD_FILE
                cli_password_file      = currentValue

        elif currentArgument in ("-t", "--text_file"):
            debugLog("-t " + currentValue + " found")
            if current_operation_mode == IM_SINGLE_PASSOWRD:
                debugLog("-t " + currentValue + " found - Ignoring due to -p parameter found first....")
            elif current_operation_mode == IM_PASSWORD_FILE:
                debugLog("-t " + currentValue + " found - Ignoring due to -f parameter found first....")
            else:
                cli_password           = ""
                current_operation_mode = IM_TEXT_FILE  
                cli_text_file          = currentValue

        elif currentArgument in ("-s", "--sha1_format"):
            debugLog("-s found... assuming everyhing in SHA1 mode from now on...")
            cli_input_mode = OM_HASH

        elif currentArgument in ("-d", "--delay"):
            debugLog("-d secs_number found... each web request will be throttled by " + str(currentValue) + "seconds")
            cli_delay_secs = int(currentValue)
             
        elif currentArgument in ("-l", "--local_sha1_file"):
            debugLog("-l " + currentValue + " found")
            if cli_db_mode != DB_LOCAL_ZIP:
                cli_db_mode    = DB_LOCAL
            cli_local_db_file  = currentValue

        elif currentArgument in ("-z", "--zipped"):
            debugLog("-z " + currentValue + " found")
            cli_db_mode    = DB_LOCAL_ZIP
            cli_local_zip  = currentValue

        elif currentArgument in ("-o", "--output_file"):
            debugLog("-o " + currentValue + " found")
            cli_output_file  = currentValue
            if cli_output_file != "": #erase the file if it exists
                outfile = open(cli_output_file, 'w', newline='\n')
                outfile.close()

        elif currentArgument in ("-h", "--help"):
            showHelp()
            print("-h or --help found - Ignoring other parameters...")
            print("PWNED - ver. " + PROGRAM_VERSION + " from A.R.")
            os._exit(ERR_NO_ERROR)
        else:
            print ("Unknow parameter")
            showHelp()
            print("PWNED - ver. " + PROGRAM_VERSION + " from A.R.")
            os._exit(ERR_WRONG_PARAMETERS)
        debugLog("cli_input_mode="+ str(cli_input_mode) + " - cli_db_mode=" + str(cli_db_mode) + " - current_operation_mode=" + str(current_operation_mode))

except getopt.error as err:
    # output error, and return with an error code
    print ("Argument parsing error: " + str(err))
    showHelp()
    print("PWNED - ver. " + PROGRAM_VERSION + " from A.R.")
    os._exit(ERR_WRONG_PARAMETERS)

#anykey("Press 'q' or Ctrl-C to quit or anything else to continue....")

if current_operation_mode == IM_SINGLE_PASSOWRD:
    assert(not(cli_password==""))
    print("Searching for a single password...: " + cli_password)
    g_number_of_password_read = 1
    checkSinglePassword(cli_password, cli_input_mode, cli_db_mode, cli_local_db_file, cli_local_zip, cli_output_file)
    printStats()

elif current_operation_mode == IM_PASSWORD_FILE:
    assert(not(cli_password_file==""))
    print("Searching for password file: " + cli_password_file)
    checkPlainPasswordFile(cli_password_file, cli_db_mode, cli_local_db_file, cli_output_file, cli_input_mode, cli_delay_secs)
    printStats()

elif current_operation_mode == IM_TEXT_FILE: 
    assert(not(cli_text_file==""))
    print("Searching for text file: " + cli_text_file)
    word_to_check_list=getPasswordList(cli_text_file)
    checkTextFile(word_to_check_list, cli_db_mode, cli_local_db_file, cli_output_file, cli_delay_secs)
    printStats()
else:
    print("UNKNOWN operation mode. this should NEVER happen. Need one of -p -f -t parameters. Use -h or --help to see usage")
    print("current arguments: "+ str(argumentList))
    printStats()
    print("PWNED - ver. " + PROGRAM_VERSION + " from A.R.")
    showHelpShort()
    os._exit(ERR_OPMODE_UNKNOWN)

if cli_output_file != "":
    print("Passwords and status are recorded to: " + cli_output_file)
    print("Remember to REMOVE THIS FILE!!!!!!!! it MAY contains your passwords.... ")
else:
    print("Password not recorded. To record use the cli option: -o outputfilename")
print("PWNED - ver. " + PROGRAM_VERSION + " from A.R. - SSL Check is now " + str(SSL_CHECK) + ". To change update value on SSL_CHECK variable")
os._exit(ERR_NO_ERROR)

