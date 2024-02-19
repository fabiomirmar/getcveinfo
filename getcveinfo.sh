#!/bin/bash

###### VARIABLES  ######
# Inform date range
dot1_date=$1
dot2_date=$2
# Inform release
release=$3
########################

if [[ -z $dot1_date || -z $dot2_date || -z $release ]]; then
	echo "Reading variables. Optionally run the command as ./getcveinfo.sh BEGIN_DATE END_DATE RELEASE"
	read -p "Enter Begin date (YYYY-MM-DD): " dot1_date
	read -p "Enter End date (YYYY-MM-DD): " dot2_date
	read -p "Enter Release (i.e.: truty, bionic, focal, etc): " release

	if [[ -z $dot1_date || -z $dot2_date || -z $release ]]; then
		echo 'one or more variables are undefined'
		exit 1
	fi
fi

# Prepare working directory
append=${RANDOM}
dirname=$(echo "/tmp/tempdir-$append")
mkdir $dirname

# Download USN database
wget -q https://people.canonical.com/~ubuntu-security/usn/database.json.bz2 -O $dirname/database.json.bz2
bzip2 -d $dirname/database.json.bz2

# Prepare filter
start=$(date -d $dot1_date +%s)
end=$(date -d $dot2_date +%s)

cat > $dirname/filter <<- EOF
.[] | select(
   .timestamp > $start and
   .timestamp < $end and
   .releases.$release
)
EOF

# Get all USNs for $release between start and end date
jq -f $dirname/filter $dirname/database.json | \
	jq ". | {USN:.id, Title:.title, Description:.description, Packages:.releases.$release.binaries, Date: (.timestamp|todate), CVEs: .cves}" \
	> $dirname/$release.json

# Extract the CVE numbers for each USN
jq . $dirname/$release.json | jq -r .CVEs | grep CVE  | sort | uniq | cut -d \" -f 2  > $dirname/"$release"_cves

# Categorize the CVEs by Priority
if [ -d /tmp/ubuntu-cve-tracker ]; then
	cd /tmp/ubuntu-cve-tracker
	git pull -q
else
	git clone -q git+ssh://fabio.martins@git.launchpad.net/ubuntu-cve-tracker /tmp/ubuntu-cve-tracker
fi

for cve in `cat $dirname/"$release"_cves`; do \
	grep -w Priority /tmp/ubuntu-cve-tracker/retired/$cve \
       	/tmp/ubuntu-cve-tracker/ignored/$cve \
       	/tmp/ubuntu-cve-tracker/embargoed/$cve \
       	/tmp/ubuntu-cve-tracker/active/$cve; done \
       	2> /dev/null > $dirname/"$release"_cves_priority

# Total CVE count
echo "Total $release CVEs: $(cat $dirname/"$release"_cves | wc -l)"

# Count CVEs per priority
echo "Negligible $release CVEs: $(grep -i negligible $dirname/"$release"_cves_priority | wc -l)"
echo "Low $release CVEs: $(grep -i low $dirname/"$release"_cves_priority | wc -l)"
echo "Medium $release CVEs: $(grep -i medium $dirname/"$release"_cves_priority | wc -l)"
echo "High $release CVEs: $(grep -i high $dirname/"$release"_cves_priority | wc -l)"
echo "Critical $release CVEs: $(grep -i critical $dirname/"$release"_cves_priority | wc -l)"

# Clean up temp directory
rm -rf $dirname
