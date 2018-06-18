#! python3
# sample demonstration of Cloud Insight Tacoma API endpoint to download reports

from __future__ import print_function
import json, requests, csv, gzip, os, time, argparse, sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning

#suppres warning for certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#CLOUD INSIGHT CREDENTIALS
EMAIL_ADDRESS=""
PASSWORD=""

#Choose ALL to pick all columns, or choose SELECT if you want to use specificy column index
RUN_MODE="ALL"

#TARGET PARENT CID and CSV Column to select by order
CI_TARGET_CID=""
KEEP_COL_INDICES = [26, 10, 8, 6, 2, 23, 36, 17, 35, 34, 39, 14, 18, 16]
CVSS_COL_INDICES = 11
MAX_CVSS_SCORE = 9

#OUTPUT FILE LOCATION
GZIP_TARGET = "./GZIP/"
RAW_CSV_TARGET = "./REPORTS/"
FINAL_CSV_TARGET = "./RESULTS/"
#Temp storage of all CID under parent CID
TARGET_DIC = []

#Hardcoded Tacoma API ID
TARGET_SITE = "d741e65f-4498-48e8-b5ae-6ea3b270654e"
TARGET_WORKBOOK = "d1434148-342d-45ca-bc94-e44dc3e68f92"
TARGET_VIEW = "9c8ddea0-9abd-4816-a036-261f65d87dd3"
#API headers and url
HEADERS = {'content-type': 'application/json'}
CID_HEADERS = {'Accept': 'application/json'}
YARP_URL="api.cloudinsight.alertlogic.com"
ALERT_LOGIC_CID = "https://api.cloudinsight.alertlogic.com/aims/v1/"
ALERT_LOGIC_CI_ASSETS = "https://api.cloudinsight.alertlogic.com/assets/v1/"
ALERT_LOGIC_CI_ENV = "https://api.cloudinsight.alertlogic.com/environments/v1/"
ALERT_LOGIC_CI_TACOMA = "https://api.cloudinsight.alertlogic.com/tacoma/v1/"
ALERT_LOGIC_ENTITLEMENT = "https://api.global.alertlogic.com/subscriptions/v1/"

def get_CID(target_cid, token):
	API_ENDPOINT = ALERT_LOGIC_CID + target_cid + "/accounts/managed?active=true"
	REQUEST = requests.get(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)
	RESULT = json.loads(REQUEST.text)
	return RESULT

def get_ci_workbook_per_cid(target_cid, target_site, target_wbid, target_viewid, token):
	API_ENDPOINT = ALERT_LOGIC_CI_TACOMA + target_cid + "/sites/" + target_site + "/workbooks/" + target_wbid + "/views/" + target_viewid + "/export"
	REQUEST = requests.get(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)
	RESULT = REQUEST.content
	return RESULT

def check_entitlement(target_cid, target_product, token):
	API_ENDPOINT = ALERT_LOGIC_ENTITLEMENT + target_cid + "/entitlements"
	REQUEST = requests.get(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)
	RESULT = json.loads(REQUEST.text)
	PRODUCT_LIC = False
	for license in RESULT["entitlements"]:
		if license["product_family"] == target_product:
			if license["status"] == "active":
				PRODUCT_LIC = license
				break
	return PRODUCT_LIC

def authenticate(user, paswd,yarp):
	#Authenticate with CI yarp to get token
	url = yarp
	user = user
	password = paswd
	r = requests.post('https://{0}/aims/v1/authenticate'.format(url), auth=(user, password), verify=False)
	if r.status_code != 200:
		sys.exit("Unable to authenticate %s" % (r.status_code))
	account_id = json.loads(r.text)['authentication']['user']['account_id']
	token = r.json()['authentication']['token']
	return token

def search_and_download(target_dic,token):
	#define the output filename
	TIMESTAMP = time.strftime("%Y%m%d-%H%M%S")
	FINAL_CSV_NAME = FINAL_CSV_TARGET + TIMESTAMP + "-combined_reports.csv"

	for item in target_dic:
		print ("CID : " + str(item["id"]) + " Name : " + str(item["name"]))
		#Check entitlement before download
		if check_entitlement(str(item["id"]),"cloud_insight", token):
			print (" downloading original reports and extracting ...")
			#Download default view from Tacoma
			TACOMA = get_ci_workbook_per_cid(str(item["id"]), TARGET_SITE, TARGET_WORKBOOK, TARGET_VIEW, token)

			#Unzip the file and write to CSV
			FILE_ZIP_NAME = GZIP_TARGET + TIMESTAMP + str(item["name"]) + ".gzip"
			os.makedirs(os.path.dirname(FILE_ZIP_NAME), exist_ok=True)
			OUTPUT_GZIP = open(FILE_ZIP_NAME, "wb")
			OUTPUT_GZIP.write(TACOMA)
			OUTPUT_GZIP.close()

			INPUT_GZIP = gzip.open(FILE_ZIP_NAME, 'rb')
			FILE_CSV_NAME = RAW_CSV_TARGET + TIMESTAMP + str(item["name"]) + ".csv"
			os.makedirs(os.path.dirname(FILE_CSV_NAME), exist_ok=True)
			OUTPUT_CSV = open(FILE_CSV_NAME, "wb")
			OUTPUT_CSV.write( INPUT_GZIP.read() )

			INPUT_GZIP.close()
			OUTPUT_CSV.close()

			print (" RAW output file stored at: " + str(FILE_CSV_NAME))
			#Process the raw CSV and pick only the column that you want
			open_and_split(FILE_CSV_NAME, FINAL_CSV_NAME, RUN_MODE)
			print ("\n")
		else:
			print (" skip CID, no Cloud Insight entitlement\n")

def isFloat(string):
    try:
        float(string)
        return True
    except ValueError:
        return False

def open_and_split(input_file_name, output_file_name, run_mode):

	INPUT_CSV_NAME = input_file_name
	OUTPUT_CSV_NAME = output_file_name
	os.makedirs(os.path.dirname(OUTPUT_CSV_NAME), exist_ok=True)

	with open(INPUT_CSV_NAME, "rt") as INPUT_CSV:
		CSV_READER = csv.reader(INPUT_CSV, delimiter=",")
		if (len(list(CSV_READER))) > 1:
			INPUT_CSV.seek(0)

			#If file not exist, create a new one
			if not os.path.exists(OUTPUT_CSV_NAME):
				open (OUTPUT_CSV_NAME, 'w').close()
				has_header = False
			else:
				#check if existing output file has header
				with open (OUTPUT_CSV_NAME, "r", newline= '') as CURRENT_OUTPUT:
					has_header = csv.Sniffer().has_header(CURRENT_OUTPUT.read(1024))

			with open (OUTPUT_CSV_NAME, "a", newline= '') as OUTPUT_CSV:
				CSV_WRITER = csv.writer(OUTPUT_CSV, delimiter=",")

				if has_header:
					next(INPUT_CSV)

				for row in CSV_READER:
					if run_mode == "ALL":
						if isFloat(row[CVSS_COL_INDICES]):
							if float(row[CVSS_COL_INDICES]) < MAX_CVSS_SCORE:
								CSV_WRITER.writerow(row)
						else:
							CSV_WRITER.writerow(row)
					elif run_mode == "LIMITED":
						if isFloat(row[CVSS_COL_INDICES]):
							if float(row[CVSS_COL_INDICES]) < MAX_CVSS_SCORE:
								CSV_WRITER.writerow([row[i] for i in KEEP_COL_INDICES])
						else:
							CSV_WRITER.writerow([row[i] for i in KEEP_COL_INDICES])

	print (" Processed output file stored at: " + str(OUTPUT_CSV_NAME))

#MAIN MODULE
if __name__ == '__main__':
	#Prepare parser and argument
	parent_parser = argparse.ArgumentParser()

	#REQUIRED PARSER
	required_parser = parent_parser.add_argument_group("Required arguments")
	required_parser.add_argument("--user", required=True, help="User name / email address for Insight API Authentication")
	required_parser.add_argument("--pswd", required=True, help="Password for Insight API Authentication")
	required_parser.add_argument("--dc", required=True, help="Alert Logic Data center assignment, i.e. defender-us-denver, defender-us-ashburn or defender-uk-newport")
	required_parser.add_argument("--cid", required=True, help="Target Alert Logic Customer ID for processing")
	required_parser.add_argument("--mode", required=True, help="Set to ALL to download all fields, use LIMITED for filtering specific fields")

	try:
		args = parent_parser.parse_args()
	except:
		EXIT_CODE = 1
		sys.exit(EXIT_CODE)

	if args.dc == "defender-us-denver" or args.dc == "defender-us-ashburn":
		ALERT_LOGIC_CID = "https://api.cloudinsight.alertlogic.com/aims/v1/"
		ALERT_LOGIC_CI_ASSETS = "https://api.cloudinsight.alertlogic.com/assets/v1/"
		ALERT_LOGIC_CI_ENV = "https://api.cloudinsight.alertlogic.com/environments/v1/"
		ALERT_LOGIC_CI_TACOMA = "https://api.cloudinsight.alertlogic.com/tacoma/v1/"
		ALERT_LOGIC_ENTITLEMENT = "https://api.global.alertlogic.com/subscriptions/v1/"
	elif args.dc == "defender-uk-newport":
		ALERT_LOGIC_CID = "https://api.cloudinsight.alertlogic.co.uk/aims/v1/"
		ALERT_LOGIC_CI_ASSETS = "https://api.cloudinsight.alertlogic.co.uk/assets/v1/"
		ALERT_LOGIC_CI_ENV = "https://api.cloudinsight.alertlogic.co.uk/environments/v1/"
		ALERT_LOGIC_CI_TACOMA = "https://api.cloudinsight.alertlogic.co.uk/tacoma/v1/"
		ALERT_LOGIC_ENTITLEMENT = "https://api.global.alertlogic.co.uk/subscriptions/v1/"

	CI_TARGET_CID = args.cid
	EMAIL_ADDRESS = args.user
	PASSWORD = args.pswd
	RUN_MODE = args.mode

	#Authenticate to Insight API
	TOKEN = str(authenticate(EMAIL_ADDRESS, PASSWORD, YARP_URL))

	#Get child CID
	TARGET_DIC = get_CID(CI_TARGET_CID, TOKEN)

	#Search per child CID and store reports
	search_and_download(TARGET_DIC["accounts"],TOKEN)
