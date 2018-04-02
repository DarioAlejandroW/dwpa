dwpa
====

Distributed WPA PSK auditor

This version includes my changes to help_crack.py:

      hccapx log file
      cracked PSK log file
      local generation of candidates based on essid and bssid.
  
  To use, use "--ad cracked.txt" option.

Requirements:

  -must have a file called "all.potfiles.txt" loaded with additional candidates. It will be coppied into cracked.txt
  
  -Routerkeygen with modified "WirelessMatcher.cpp" file with all restrictions removed. 
  -Note: will run stock version in -q mode but with fewer candidates. (Currently disabled)
  
Included routines that manipulate the essid as follows:
    Strips essid of -_:,. and <space>
    Extracts all substrings of length 4 or more
    Converts them to raw, lower, upper, and capital case
    Adds common 3 digit ending, 1234-1234567890 endings, 0-9 endings, rotates right and left, adds spaces across string
    Adds years from 1921 to 2020 to each substring
Manipulates bssid as follows:
  Increment bssid from -16 to +16. 
  Extract substrings length 8 to 12. 
  Add prefix A-Z 0-9. 
  Add last 6 incremented digits of bssid  to essid substring. 
   
  Examples:
  
    1c:fa:68:a6:90:ce|yang2618|2618yang           rotate right
  
    00:2e:c7:c4:8a:e0|Ngopi Heula|ngopiheula      remove space, lower case
    
    8c:e1:17:ba:66:71|true_home2G_671|17ba6671    bssid substring
    
    b0:b2:dc:52:bd:64|RASYONAL|Rasyo2012          essid substring with year added
    
    14:b7:f8:e4:f5:95|TC8715D8F|TC8715DE4F58F     essid substring and bssid substring
    
    1c:7e:e5:3c:b6:26|mansourah_admin|mansourah4  essid substring with 1 digit suffix
    
    00:0c:42:31:43:1e|Sjotun Camping|camping007   essid substring with common 3 digit suffix
    

NOTE: these are hacks I have developed over time, and the code may be a little sloppy. Sorry..I'll get around
      to cleaning it up someday, but at least it works.

Live installation:

http://wpa-sec.stanev.org

To install dwpa on your server, please refer to [INSTALL.md](INSTALL.md)
