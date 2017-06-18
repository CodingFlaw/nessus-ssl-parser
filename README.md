# nessus-ssl-parser
A quick ruby script for parsing SSL/TLS issues from Nessus files.

Usage:

  nessus_ssl_parser.rb [options] nessus_file_location  
  -h, --help       Show this help.  
  -v, --version    Show the version number.  
  -l, --logfile    Specify the filename for output.  
  -i, --isseus     List by issue.  
  -ip              List by IP   
  -r, --risk       Include all risk levels above X (All = 0, Low = 1, Medium = 2, High = 3, Critical = 4)  
  -V. --verbose    Output in verbose mode. (ONLY IMPLEMENTED FOR ISSUE LIST)  
