#!/bin/bash

# Use these variables to control what TCP ports are checked for http and https web urls.
# тут надо пополнить еще если пропустили
webHttpPorts="80 8000 8080 9080 9182 10050 9200 2601 2604  1299  2009 8008 8009  5985 8001 9002 9009 9010 47001 5100 23 1200 7009 7080 10000 5060 81 2000 8282 9100 5022 "
webHttpsPorts="443 8443 9443 8089 6701 4443 5062 11443 10443 1300 2944 8765"

thisYMDHM=$(date +%F-%H-%M)
outDir="results-nmap-parsing-$thisYMDHM"
csvFile="CSV-version-results-$thisYMDHM.csv"
webUrlsFile="weburls-for-nuclei-$thisYMDHM.txt"
summaryFile="summary-entire-results$thisYMDHM.txt"

function fnUsage {
  echo
  echo "========================================[ about ]========================================"
  echo
  echo "Shell script for parsing Nmap scan results."
  echo
  echo "Detects source file format by checking for:"
  echo "-'/open/' (gnmap)"
  echo "-'port protocol=' (xml)"
  echo "-'Nmap scan report for' (nmap)"
  echo
  echo "Creates:"
  echo "-CSV list of ip,protocol,port,name,version info"
  echo "-Lists of IPs for each port as [protocol]-[port]-hosts.txt"
  echo "-List of web urls for customizable lists of HTTP and HTTPS ports"
  echo "-Summary report table"
  echo
  echo "Created $dateCreated, last modified $dateLastMod."
  echo
  echo "========================================[ usage ]========================================"
  echo
  echo "./nmaparse.sh [source file] [--out-dir [path]]"
  echo
  echo "[source file]     Nmap output file to read from. Must be the first parameter."
  echo
  echo "--out-dir [path]  Optionally specify an output directory. The default is"
  echo "                  nmaparse-YYYY-MM-DD-HH-MM/."
  echo
  echo "=========================================[ fin ]========================================="
  echo
  exit
}

function fnXmlToCsv {
  # Reduce file to IPv4 addresses and ports to eliminate reading unnecessary lines
  grep 'addrtype="ipv4"\|state state="open"' "$sourceFile" --color=never > "$outDir"/"working-src-$thisYMDHM.txt"
  # Convert to CSV
  while read -r thisLine; do
    # Find start point for new host address
    checkNewHost=$(echo "$thisLine" | grep "address addr=")
    if [ "$checkNewHost" != "" ]; then
     
      thisHost=$(echo "$thisLine" | awk -F \" '{print $2}')
      
    fi
    # Find and parse port result
    checkPortResult=$(echo "$thisLine" | grep "port protocol=")
    if [ "$checkPortResult" != "" ]; then
      thisProto=$(echo "$thisLine" | grep -o "protocol=.*" | awk -F \" '{print $2}')
      thisPort=$(echo "$thisLine" | grep -o "portid=.*" | awk -F \" '{print $2}')
      thisName=$(echo "$thisLine" | grep -o "service name=.*" | awk -F \" '{print $2}')
      thisProduct=$(echo "$thisLine" | grep -o "product=.*" | awk -F \" '{print $2}')
      thisVersion=$(echo "$thisLine" | grep -o "version=.*" | awk -F \" '{print $2}')
      echo "$thisHost,$thisProto,$thisPort,$thisName,$thisProduct $thisVersion" | sed 's/ $//g' | sed 's/,$//g' >> "$outDir"/"working-csv-$thisYMDHM.txt"
    
    fi
  done < "$outDir"/"working-src-$thisYMDHM.txt"
  if [ -f "$outDir"/"working-src-$thisYMDHM.txt" ]; then rm "$outDir"/"working-src-$thisYMDHM.txt"; fi
  # Convert unsorted working CSV into sorted final CSV
  sort -Vu "$outDir"/"working-csv-$thisYMDHM.txt" | grep -v "tcpwrapped" > "$outDir"/"$csvFile"
  if [ -f "$outDir"/"working-csv-$thisYMDHM.txt" ]; then rm "$outDir"/"working-csv-$thisYMDHM.txt"; fi
}

function fnGnmapToCsv {
  # Reduce file to lines with open ports to eliminate reading unnecessary lines
  grep '/open/' "$sourceFile" --color=never > "$outDir"/"working-src-$thisYMDHM.txt"
  # Convert to CSV
  while read -r thisLine; do
    # Get host address
    thisHost=$(echo "$thisLine" | awk '{print $2}')
    # Parse open port results
    
    echo "$thisLine" | awk '{$1=$2=$3=$4=""; print $0}' | sed 's/\/,/\/\n/g' | sed 's/^ *//g' | grep '/open/' | awk -v awkHost="$thisHost" -F / '{print awkHost "," $3 "," $1 "," $5 "," $7}' | awk -F \( '{print $1}' | sed 's/,$//g' >> "$outDir"/"working-csv-$thisYMDHM.txt"
  done < "$outDir"/"working-src-$thisYMDHM.txt"
  if [ -f "$outDir"/"working-src-$thisYMDHM.txt" ]; then rm "$outDir"/"working-src-$thisYMDHM.txt"; fi
  # Convert unsorted working CSV into sorted final CSV
  sort -Vu "$outDir"/"working-csv-$thisYMDHM.txt" | grep -v "tcpwrapped" > "$outDir"/"$csvFile"
  if [ -f "$outDir"/"working-csv-$thisYMDHM.txt" ]; then rm "$outDir"/"working-csv-$thisYMDHM.txt"; fi  
}

function fnNmapToCsv {
  # Reduce file to lines that start hosts or contain open ports to eliminate reading unnecessary lines
  grep 'Nmap scan report for \| open ' "$sourceFile" --color=never > "$outDir"/"working-src-$thisYMDHM.txt"
  # Convert to CSV
  echo 'Generating jaeles_list'
  while read -r thisLine; do
    # Find start point for new host address
    checkNewHost=$(echo "$thisLine" | grep "Nmap scan report for")
    if [ "$checkNewHost" != "" ]; then
      thisHost=$(echo "$thisLine" | awk '{print $NF}' | tr -d "()")
      echo http://$thisHost >> $outDir/'jaeles_list'
    fi
    # Find and parse port result
    checkPortResult=$(echo "$thisLine" | grep '[[:digit:]]*/.* open ')
    if [ "$checkPortResult" != "" ]; then
      thisProto=$(echo "$thisLine" | awk '{print $1}' | awk -F / '{print $2}')
      thisPort=$(echo "$thisLine" | awk '{print $1}' | awk -F / '{print $1}')
      thisName=$(echo "$thisLine" | awk '{print $3}')
      thisVersion=$(echo "$thisLine" | awk '{$1=$2=$3=""; print $0}' | sed 's/^ *//g' | awk -F \( '{print $1}')
      echo "$thisHost,$thisProto,$thisPort,$thisName,$thisVersion" | sed 's/ $//g' | sed 's/,$//g' >> "$outDir"/"working-csv-$thisYMDHM.txt"
    fi
  done < "$outDir"/"working-src-$thisYMDHM.txt"
  if [ -f "$outDir"/"working-src-$thisYMDHM.txt" ]; then rm "$outDir"/"working-src-$thisYMDHM.txt"; fi
  # Convert unsorted working CSV into sorted final CSV
  sort -Vu "$outDir"/"working-csv-$thisYMDHM.txt" | grep -v "tcpwrapped" > "$outDir"/"$csvFile"
  if [ -f "$outDir"/"working-csv-$thisYMDHM.txt" ]; then rm "$outDir"/"working-csv-$thisYMDHM.txt"; fi
}


function fnCsvToLists {
  for thisUniqProtoPort in $(cat "$outDir"/"$csvFile" | awk -F , '{print $2 "," $3 ","}' | sort -Vu ); do
    thisProto=$(echo "$thisUniqProtoPort" | awk -F , '{print $1}')
    thisPort=$(echo "$thisUniqProtoPort" | awk -F , '{print $2}')
    grep "$thisUniqProtoPort" "$outDir"/"$csvFile" --color=never | awk -F , '{print $1}' | sort -Vu >> "$outDir"/"$thisProto-$thisPort-hosts.txt"
    
  done
}

function fnSummary {
  echo "+------------------+--------------+-----------------------------------------------------+" >> "$outDir"/"$summaryFile"
  printf "%-18s %-14s %-52.52s %-2s \n" "| HOST " "| OPEN PORT " "| PROTOCOL - SERVICE" " |" >> "$outDir"/"$summaryFile"
  lastHost=""
  while read thisLine; do
    thisLineHost=""
    thisLinePort=""
    thisLineProto=""
    thisLineName=""
    thisLineSvc=""
    thisLineHost=$(echo $thisLine | awk -F , '{print $1}')
    thisLinePort=$(echo $thisLine | awk -F , '{print $3}')
    thisLineProto=$(echo $thisLine | awk -F , '{print $2}')
    thisLineName=$(echo $thisLine | awk -F , '{print $4}')
    thisLineSvc=$(echo $thisLine | awk -F , '{print $5}')
    if [ "$thisLineHost" != "$lastHost" ]; then echo "+------------------+--------------+-----------------------------------------------------+" >> "$outDir"/"$summaryFile"; fi
    if [ "$thisLineSvc" = "" ]; then
      thisLineSvc=""
    else
      thisLineSvc="- $thisLineSvc"
    fi
    printf "%-18s %-14s %-52.52s %-2s \n" "| $thisLineHost " "| $thisLinePort / $thisLineProto " "| $thisLineName $thisLineSvc" " |" >> "$outDir"/"$summaryFile"
    echo $thisLineHost":"$thisLinePort >> "$outDir"/"for_curl-list"
    
   

    
    lastHost="$thisLineHost"
  done < "$outDir"/"$csvFile"
  echo "+------------------+--------------+-----------------------------------------------------+" >> "$outDir"/"$summaryFile"
}

echo
echo "=======================[ For Visum usage ]======================="

# Set source file
sourceFile="$1"
shift

# Check source file
if [ "$sourceFile" = "" ]; then
  echo
  echo "Error: No source file given."
  fnUsage
fi

# Check source file format
checkGnmapResults=$(grep '/open/' "$sourceFile")
checkXmlResults=$(grep "port protocol=" "$sourceFile")
checkNmapResults=$(grep "Nmap scan report for" "$sourceFile")
sourceFormat="NOTSET"
if [ "$checkGnmapResults" != "" ]; then
  sourceFormat="GNMAP"
elif [ "$checkXmlResults" != "" ]; then
  sourceFormat="XML"
elif [ "$checkNmapResults" != "" ]; then
  sourceFormat="NMAP"
else
  echo
  echo "Error: Could not gnmap, xml, or nmap results in $sourceFile."
  fnUsage
fi

# Check for output directory option
if [ "$1" = "--out-dir" ]; then
  outDir="$2"
  if [ "$outDir" = "" ]; then
    echo
    echo "Error: --out-dir option with no directory given."
    fnUsage;
  fi
fi

# Check whether output directory exists
if [ -d "$outDir" ]; then
  echo
  echo "Warning: Output directory '$outDir' exists, files may be appended."
  read -p "Press Enter to continue..."
elif [ -e "$outDir" ] && [ ! -d "$outDir" ]; then
  echo
  echo "Error: Output directory '$outDir' exists and is not a directory."
  fnUsage
else
  mkdir "$outDir"
fi

# Convert source file to CSV based on source format
echo
echo -n "Parsing source file..."
if [ "$sourceFormat" = "GNMAP" ]; then
  fnGnmapToCsv
elif [ "$sourceFormat" = "XML" ]; then
  fnXmlToCsv
elif [ "$sourceFormat" = "NMAP" ]; then
  fnNmapToCsv
fi
echo " Done."

# Split lists of hosts from CSV file
if [ -f "$outDir"/"$csvFile" ]; then
  
  fnCsvToLists
 
  #wc -l "$outDir"/*-*-hosts.txt
fi

# Create list of web urls
for thisWebPort in $webHttpPorts; do
  if [ -f "$outDir"/"tcp-$thisWebPort-hosts.txt" ]; then
    awk -v awkWebPort="$thisWebPort" '{print "http://" $1 ":" awkWebPort "/"}' "$outDir"/"tcp-$thisWebPort-hosts.txt" >> "$outDir"/"$webUrlsFile"
  fi
done
for thisWebPort in $webHttpsPorts; do
  if [ -f "$outDir"/"tcp-$thisWebPort-hosts.txt" ]; then
    awk -v awkWebPort="$thisWebPort" '{print "https://" $1 ":" awkWebPort "/"}' "$outDir"/"tcp-$thisWebPort-hosts.txt" >> "$outDir"/"$webUrlsFile"
  fi
done
if [ -f "$outDir"/"$webUrlsFile" ]; then
  echo
  echo "$webUrlsFile created."
fi

# Create a summary report
if [ -f "$outDir"/"$csvFile" ]; then
  echo
  echo -n "Creating summary report..."
  fnSummary
  echo " $summaryFile created."
fi


#cat $sourceFile | grep 'Nmap scan report for' | 

####### for jaeles list


##### checking live HTTP/HTTPS  ========SOOOOOOON 


#cat $sourceFile |  grep "^Nmap scan" | tr -s 'Nmap scan report for' ' ' > IP.txt грепает айпи
#curle="curl -sw '%{http_code}' $urls"
#lest=$outDir/$webUrlsFile 
#echo $lest
#
#spisok=cat $lest 
#echo $spisok
#for urls in $spisok
#do 
#  echo $curle
#  echo 'vdvdvdvddv'
#done

#while read urls; do curl -sw '%{http_code}' $urls; done < $outDir/$webUrlsFile
# curl -I   http://ya.ru | head -1 | awk '{print $2}'

echo
echo "=========================================[ proccess has been completed ]========================================="
echo


### clean up trash of hosts files
var_list=`ls $outDir/*hosts.txt`
for eachfile in $var_list
do
   rm $eachfile
done




##to do tasks

#1 check automated for existence the http/https via curl 
#2 
