#!/usr/bin/python3
import json
import argparse
import requests

iq_url, creds, iq_session, LTGs, licenses = "", "", requests.Session(), {}, {}
iq_session.cookies.set('CLM-CSRF-TOKEN', 'api')
iq_headers = {'X-CSRF-TOKEN': 'api'}

def getArguments():
	global iq_url, iq_session, creds
	parser = argparse.ArgumentParser(description='Export Policy')
	parser.add_argument('-u','--url', help='', default="http://localhost:8070", required=False)
	parser.add_argument('-a','--auth', help='', default="admin:admin123", required=False)
	args = vars(parser.parse_args())
	iq_url = args["url"]
	creds = args["auth"].split(":")
	iq_session.auth = requests.auth.HTTPBasicAuth(creds[0], creds[1])
	return args

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def main():
	args = getArguments()
	build_LicenseThreatGroups()

	# print (json.dumps(LTGs, indent=4))
	# print (json.dumps(licenses, indent=4))
	export_LTGs("iq-export-LTG.csv")

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def export_LTGs(filename):
	with open(filename,'w') as f:
		c = ["LTG","ShortName","LongName"]
		f.write(",".join(c)+"\n")
		for key, ltg in LTGs.items():
			name = ltg["name"]
			for license in ltg["licenses"]:
				l = licenses[license]
				c = [name, l["shortDisplayName"], l["longDisplayName"]]
				f.write(",".join(c)+"\n")

		for key, lics in licenses.items():
			if lics["count"] == 0:
				c = ["Not Classified", lics["shortDisplayName"], lics["longDisplayName"]]
				f.write(",".join(c)+"\n")

def build_LicenseThreatGroups():
	global LTGs, licenses

	#export of policy
	url = f'{iq_url}/rest/policy/organization/ROOT_ORGANIZATION_ID/export'
	policy = iq_session.get(url).json()

	#dict of licenses by license_Id
	for o in iq_session.get(f'{iq_url}/rest/license').json():
		o.update({"count":0, "LTGid": [] })
		licenses.update({ o["id"] : o })

	#dict of LTGs by LTG_id
	for o in policy["licenseThreatGroups"]:
		o.update({"licenses":[]})
		LTGs.update({ o["id"] : o })

	for o in policy["licenseThreatGroupLicenses"]:
		license_id = o['licenseId']
		LTGid = o["id"]
		licenses[license_id]["count"] += 1
		licenses[license_id]["LTGid"].append( LTGid )
		LTGs[o["licenseThreatGroupId"]]["licenses"].append( license_id )

#-----------------------------------------------------------------------------
# run main on launch
#-----------------------------------------------------------------------------
if __name__ == "__main__":
	main()
