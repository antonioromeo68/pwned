# pwned.py
pwned.py is Python program written to check if a password has been pwned (i.e. has been seen in a data breach in the past).
It uses a web services provided by the https://haveibeenpwned.com/ web site (which I am NOT affiliated or associated with) OR can use a local pwd DB 
(really a text file).
For local usage, it expect a txt password file containing passwords hashed in SHA1 format. The file can now be zipped.

Example of password file formats:
#frequency:sha1-hash:plain
#this format has the original password in the file... not used by the program
something:7C4A8D09CA3762AF61E59520943DC26494F8941B:123456
something:f7c3bc1d808e04732adf679965ccc34ca7ae3441:123456789
#this format only contains the hashed password (and number of times it has been found in breaches).
7C4A8D09CA3762AF61E59520943DC26494F8941B:37359195
F7C3BC1D808E04732ADF679965CCC34CA7AE3441:16629796
B1B3773A05C0ED0176787A4F1574FF0075F7521E:10556095

You can use this program at your own risk.


