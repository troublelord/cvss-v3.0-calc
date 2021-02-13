from math import ceil
import argparse
import sys


cvssWeight={'AV':{'N':0.85,'A':0.62,'L':0.55,'P':0.2},'AC':{'H':0.44,'L':0.77},'PR':{'U':{'N':0.85,'L':0.62,'H':0.27},'C':{'N':0.85,'L':0.68,'H':0.5}},'UI':{'N':0.85,'R':0.62},'S':{'U':6.42,'C':7.52},'C':{'N':0,'L':0.22,'H':0.56},'I':{'N':0,'L':0.22,'H':0.56},'A':{'N':0,'L':0.22,'H':0.56}}

def parse(cvss):
	cvssDict = {}
	for factor in cvss:
		cvssDict[factor.split(':')[0].strip().upper()] = factor.split(':')[1].strip().upper()

	return cvssDict

def cvss_calc(cvss):
	cvss = cvss.split('/')
	
	if(cvss[0].split(':')[1]=='3.0'):
		cvssDict = parse(cvss[1:])
		
		iscBase = 1 - ( ( 1 - cvssWeight['C'][cvssDict['C']] ) * ( 1 - cvssWeight['I'][cvssDict['I']] ) *  ( 1 - cvssWeight['A'][cvssDict['A']] ) )

		if(cvssDict['S']=='U'):
			exp_SubScore = 8.22 * cvssWeight['AV'][cvssDict['AV']] * cvssWeight['AC'][cvssDict['AC']] * cvssWeight['PR']['U'][cvssDict['PR']] * cvssWeight['UI'][cvssDict['UI']]
			imp_SubScore = 6.42 * iscBase
			if(imp_SubScore <= 0):
				return 0

			return ceil( min( (imp_SubScore + exp_SubScore), 10 ) * 10 ) / 10

		elif(cvssDict['S']=='C'):
			exp_SubScore = 8.22 * cvssWeight['AV'][cvssDict['AV']] * cvssWeight['AC'][cvssDict['AC']] * cvssWeight['PR']['C'][cvssDict['PR']] * cvssWeight['UI'][cvssDict['UI']]
			imp_SubScore = ( 7.52 * (iscBase - 0.029) ) - ( 3.25 * ((iscBase - 0.02) ** 15) )
			if(imp_SubScore <= 0):
				return 0

			return ceil( min( 1.08 * (imp_SubScore + exp_SubScore), 10 ) * 10 ) / 10

		else:
			print("[!] CVSS vector is malformed")
			return -1

	else:
		print("[!] The provided CVSS vector is not v3.0")
		#print("[!] eg: CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:H")
		return -1




if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Process')
	parser = argparse.ArgumentParser()
	parser.add_argument('-c', '--cvss', nargs='+', type=str, help="[+] Used to specify CVSS vector string")
	#parser.add_argument('-v', dest='verbose', action='store_true')
	args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
	
	print("\n########################")
	print("# CVSS v3.0 Calculator #")
	print("########################\n")

	if(args.cvss):
		cvssVector = ' '.join(args.cvss)
		cvssScore = cvss_calc(cvssVector)
		if(cvssScore == -1 ):
			print("[!]",cvssVector)
		else:
			print("[+]",cvssScore,"(" + cvssVector + ")" )
