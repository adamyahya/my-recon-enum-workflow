# my-recon-enum-workflow


Subdomain Recon : 
mkdir -p ~/Recon/target/subdomains 
cd ~/Recon/target/subdomains 
nano exclude.txt (write out of scope targets)
# Passive Enum : 
subfinder -d target.com -all -recursive -silent -o subfinder.txt &
amass enum -passive -d target.com -o amass.txt &
chaos -d target.com -silent -o chaos.txt &
findomain -t target.com --quiet -u findomain.txt &
assetfinder --subs-only target.com > subs.txt
wait 
cat *.txt | sort -u > passive-subs.txt
Clean passive result : 
grep -E "^[a-zA-Z0-9._~.-]+\.target\.com$" passive-subs.txt > clean.txt
# DNS Resolution :
 dnsx -l clean.txt  -silent -threads 200 -o resolved-passive.txt
 Bruteforce( Active Directory) :
 puredns bruteforce ~/wordlists/best-dns-wordlist.txt target.com -r ~/resolvers.txt -o brute.txt
# Smart permutations : 
cat resolved-passive.txt | alterx -o permutations.txt
dnsx -l permutations.txt -silent -threads 200 -o resolved-permutation.txt 
# Combine all : 
cat resolved-passive.txt brute.txt resolved-permutation.txt | sort -u > all-resolved.txt
Scope Filtering : 
sort -u all-resolved.txt | grep -v -F -f exclude.txt > inscope.txt 
nuclei -l inscope.txt -t takeover/ -o nuclei-takeover.txt

# HTTP probing + Fingerprinting :
httpx -l inscope.txt -title -status-code -tech-detect -web-server -content-length -cdn -ip -cname -follow-redirects -random-agent -threads 250 -o live-full.txt -H "User-Agent: Mozilla/5.0 ..."
Filter interesting ones : 
cat live-full.txt | grep -E "200|301|302|307|401|403|500" > live.txt
Screenshot + Visual Recon : 
httpx -l live.txt -screenshot -esb -ehb -o screenshots.txt -H "User-Agent: Mozilla/5.0 ..."
# Historical data : 
gau  --headers "User-Agent: Mozilla/5.0 ..."
target.com >>wayback.txt
cat wayback.txt | grep "\.js" | sort -u > wayback-js.txt
cat wayback-js.txt | httpx  -H "User-Agent: Mozilla/5.0 ..." -silent -mc 200 -o live-js.txt
waybackcurls target.com >>wayback.txt
cat wayback.txt | unfurl domains | grep target.com |sort -u >> all-resolved.txt
#  Final live targets : 
dnsx -l all-resolved.txt -silent | httpx -H "User-Agent: Mozilla/5.0 ..." -silent -o final-live.txt 
# ASN discovery
amass intel -org "Target Company" -output asn.txt
# Extract CIDR ranges
amass intel -asn $(cat asn.txt | awk '{print $1}') -output cidr.txt
# Expand to IP list
mapcidr -cidr cidr.txt -o ips-expanded.txt
# Reverse DNS
dnsx -l ips-expanded.txt -ptr -silent -o ptr-records.txt
Content / Directory / Endpoint discovery :
cd .. 
mkdir directory-endpoint
cd directory-endpoint
ffuf -l ../subdomains/final-live.txt -w ~/wordlists/dirsearch.txt -u FUZZ -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -mc 200,204,301,302,307,401,403,500 -t 150 -ac -recursion -recursion-depth 3 -o ffuf-dir.txt
katana -H "User-Agent: Mozilla/5.0 ..."  -list ../subdomains/final-live.txt -depth 3 -js-crawl -silent -o katana-url.txt 
gospider -H "User-Agent: Mozilla/5.0 ..." -S ../subdomains/final-live.txt --depth 3 -t 20 -q -o gospider.txt
# Merge Results :
cat *.txt | sort -u > endpoint.txt
# Find sensitive files :
grep -Ei "\.git|\.env|\.bak|\.zip|\.sql|backup|config|admin|debug|dashboard|login|api|console|test|dev" endpoint.txt > sensitive.txt
Param & URL Enum :
# Extract URLs  with param :
cd ..
mkdir param
cd param 
cat directory-endpoint/endpoint.txt | grep "=" > param.txt
arjun -u https://api.target.com/v1 -oT arjun-api.json --stable
paramspider -d target.com -o paramspider.txt 
# Hidden params from JS
cat js-endpoint.txt | unfurl keys | sort -u > hidden-params.txt
# Param brute force
ffuf -u https://target.com/page?FUZZ=test -w hidden-params.txt
cat *.txt | grep -Ei "id|user|token|key|pass|admin|debug|redirect" > juicy-param.txt
# Use GF params :
cat param.txt | gf xss >xss-param.txt
cat param.txt | gf sqli>sqli-param.txt
cat param.txt | gf ssrf > ssrf-param.txt
cat param.txt |qsreplace FUZZ >fuzz-ready.txt
ffuf -u FUZZ -w fuzz-ready.txt:URL -w ~/wordlist/xss-payloads.txt -mc 200,302,403 -o ffuf-param.json 
# Port Scanning & Service Enum :
cd .. 
mkdir Port&services
cd Port&services
dnsx -l ../subdomains/inscope.txt -a -resp-silent | awk '{print $2}' | sort -u > ips.txt
# Fast Port Discovery :
rustscan -a ips.txt --ulimit 5000 -- -sS -Pn -T4 -oN rustscan.txt
# Detailed Nmap Scan :
nmap -iL ips.txt -p- -sV -sC -Pn -T4 --min-rate 1000  -oA nmap-full
or
nmap -iL rustscan.txt -sV -sC -Pn -T4 --min-rate 1000 -oA nmap-full
# Extract Open Ports :
grep "open"nmap-full.nmap >open-ports.txt 
# Service-specific Enum :
httpx -l ../subdomains/inscope.txt -p 80,443,8000,8080,8888,3000 -title -tech-detect -status-code -o web-services.txt -H "User-Agent: Mozilla/5.0 ..."
# JS analysis & Secret hunting  :
Collect js files :
cd ..
mkdir js-analysis&secret-hunting
cd js-analysis&secret-hunting
cat /subdomains/final-live.txt |katana -H "User-Agent: Mozilla/5.0 ..." -js -silent |grep "\.js"| sort -u > jsfile.txt 
Download JS:
cat jsfile.txt | xargs -n1 wget -q -P js-downloads/
Extract endpoint from JS :
python3 SecretFinder.py -i js-downloads/ -o cli > secret.txt
nuclei -l jsfile.txt -t exposure/token/ -t exposure/secrets/ -o nuclei-js-secret.txt
cat jsfile.txt | xargs -I % python3 LinkFinder.py -i % -o cli >> js-endpoint.txt
cat js-download/*.js | grep -Ei “ api-key|token|secret|aws-access|password| key |bearer| api\.”> potential-secret.txt
Prioritize :
cat js-downloads/*.js | grep -Ei "api-key|token|secret|aws-access|password|key|bearer|api\." > potential-secret.txt
# Cloud Asset discovery (S3,GCP,Azure  :
 s3scanner scan -l ../subdomains/all-resolved.txt -o s3.txt
cloud_enum -k target -l cloud.txt
ffuf -w ~/wordlists/buckets.txt -u https://FUZZ.s3.amazonaws.com -mc 200,403
Cloud Asset discovery (S3,GCP,Azure  :
# Find swagger / graphql / openapi
grep -Ei "swagger|api-docs|graphql|openapi" endpoint.txt > api-endpoints.txt

# probe them
httpx -l api-endpoints.txt -mc 200 -o live-api.txt
