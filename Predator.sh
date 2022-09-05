#!/bin/bash

echo "Usage: bash Predator.sh [domains file]"

touch subdomainDiscovery.txt
touch directoryFinding.txt
touch fileFinding.txt
touch httpServers.txt

#Wordlists
dirLocation="/home/jose/Documents/Tools/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
fileLocation="/home/jose/Documents/Tools/wordlists/SecLists/Discovery/Web-Content/raft-medium-files.txt"
toolsLocation="/home/jose/Documents/Tools/"
nucleiTemplates="/home/jose/nuclei-templates/"


#ACTIVE HUNT

#Nmap scanning
echo "Executing scanning..."
nmap -p 1-65535 -sV -sC -o FullscanResults.txt -iL $1
#nmap -p 80,443 -oG scanResults.txt -iL $1

#Trim HTTP/S servers
#grep "80/open" scanResults.txt | cut -d " " -f 2 > tmpHTTP.txt
#grep "443/open" scanResults.txt | cut -d " " -f 2 >> tmpHTTP.txt
#sort -u tmpHTTP.txt > httpServers.txt

#Resource scanning - Directories
echo "Executing directory finding..."
while read line; do gobuster -u http://$line -w $dirLocation >> directoryFinding.txt -k; done < $1
while read line; do gobuster -u https://$line -w $dirLocation >> directoryFinding.txt -k; done < $1
#Resource scanning - Files
echo "Executing file finding..."
while read line; do gobuster -u http://$line -w $fileLocation >> fileFinding.txt -k; done < $1
while read line; do gobuster -u https://$line -w $fileLocation >> fileFinding.txt -k; done < $1

# If wildcart is present, use this flag to obtain only other responses in gobuster or use ferox buster:
# -s "204,301,302,307,401,403" -> put the server responses that are not thrown in the wildcard

#Sudomain discovery
echo "Executing subdomain discovery..."
while read line; do amass enum -d $line >> subdomainDiscovery.txt ; done < $1

#Nuclei
echo "Executing vulnerability discovery..."

nuclei -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -t $nucleiTemplates"cves/" -l $1 -o nuclei-Hunt1.txt
nuclei -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -t $nucleiTemplates"default-logins/" -l $1 -o nuclei-Hunt2.txt
nuclei -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -t $nucleiTemplates"dns/" -l $1 -o nuclei-Hunt3.txt
nuclei -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -t $nucleiTemplates"exposed-panels/" -l $1 -o nuclei-Hunt4.txt
nuclei -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -t $nucleiTemplates"exposures/" -l $1 -o nuclei-Hunt5.txt
nuclei -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -t $nucleiTemplates"fuzzing/" -l $1 -o nuclei-Hunt6.txt
nuclei -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -t $nucleiTemplates"headless/" -l $1 -o nuclei-Hunt7.txt
nuclei -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -t $nucleiTemplates"iot/" -l $1 -o nuclei-Hunt8.txt
nuclei -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -t $nucleiTemplates"miscellaneous/" -l $1 -o nuclei-Hunt9.txt
nuclei -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -t $nucleiTemplates"misconfiguration/" -l $1 -o nuclei-Hunt10.txt
nuclei -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -t $nucleiTemplates"network/" -l $1 -o nuclei-Hunt11.txt
nuclei -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -t $nucleiTemplates"takeovers/" -l $1 -o nuclei-Hunt12.txt
nuclei -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -t $nucleiTemplates"technologies/" -l $1 -o nuclei-Hunt13.txt
nuclei -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -t $nucleiTemplates"vulnerabilities/" -l $1 -o nuclei-Hunt14.txt
nuclei -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -t $nucleiTemplates"workflows/" -l $1 -o nuclei-Hunt15.txt

#XSRF
echo "Executing XSRF hunt..."
while read line; do xsrfprobe -u http://$line --user-agent "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" --crawl -o $line+"xsrf-hunt.txt"; done < $1

#SubdomainTakeover
echo "Executing subdomain takeover discovery..."
python3 $toolsLocation"subTakeOver.py" -l $1 >> domainTakeover.txt

#SSRF
echo "Go run SSRFire tool manually, location:\n~/Documents/Tools/SSRFire/"
echo "\n./sshfire.sh -d [victim domain] -s [ssrftest domain]"
read -p "\nRun it for the root domains, once done write OK: " dummy

#XSS Hunt

#XSStrike - Default parameters
while read line1
    do
        while read line2
            do 
                python3 $toolsLocation"XSStrike/xsstrike.py" -u $line2 --crawl >> XXStrike-Hunt.txt
                echo "\n\n" >> XXStrike-Hunt.txt
            done < $toolsLocation"SSRFire/output/"$line1"/raw_urls.txt"
    done < $1

#XSStrike - Custom payloads


#XSS-Whole Site Hunt
echo "Executing XSS hunt..."
while read line; do python $toolsLocation"XssPy/XssPy.py" -u http://$line >> XSS-Hunt.txt; done < $1
echo "####################\n\n" >> XSS-Hunt.txt
while read line; do python3 $toolsLocation"XSSCon/xsscon.py" -u http://$line >> XSS-Hunt.txt; done < $1
echo "####################\n\n" >> XSS-Hunt.txt    
while read line; do python3 $toolsLocation"/PwnXSS/pwnxss.py" -u http://$line >> XSS-Hunt.txt; done < $1
echo "####################\n\n" >> XSS-Hunt.txt    
while read line; do python $toolsLocation"XssPy/XssPy.py" -u https://$line >> XSS-Hunt.txt; done < $1
echo "####################\n\n" >> XSS-Hunt.txt
while read line; do python3 $toolsLocation"XSSCon/xsscon.py" -u https://$line >> XSS-Hunt.txt; done < $1
echo "####################\n\n" >> XSS-Hunt.txt    
while read line; do python3 $toolsLocation"/PwnXSS/pwnxss.py" -u https://$line >> XSS-Hunt.txt; done < $1

#Find JS files 
echo "Searching for JS files..."
getJS --input $1 --insecure --verbose --output JSearch.txt  #tool requires domains with http:// in front, may need to run manually for now

#PASSIVE HUNT

#GitDorker
echo "Executing Git Hunt..."
while read line; do python3 $toolsLocation"GitDorker/GitDorker.py" -tf $toolsLocation"GitDorker/tf/TOKENSFILE" -q $line -d $toolsLocation"GitDorker/Dorks/alldorksv3" -o $line+"-dorker.txt" ; done < $1







