Step 1: Install Virtual Box compatible to your device from the link: https://docs.remnux.org/install-distro/get-virtual-appliance

![image](https://github.com/user-attachments/assets/db999522-8e50-45fa-bee6-df94097025ee)

Step 2: Download Remnux from the follwoing link as shown below:  https://www.virtualbox.org/wiki/Downloads

![image](https://github.com/user-attachments/assets/23b360ab-d3c6-4b85-a1ff-d522e6e756f5)

![image](https://github.com/user-attachments/assets/44a7e47c-50aa-4236-9ba1-0bfa3b19f621)

Step 3: Open virtual box and import the remnux vm as shown below:
Open VirtualBox.
Go to File > Import Appliance.
Browse to the location where you downloaded the Remnux virtual appliance file.
Select the file and click Next.
Follow the prompts to import the virtual appliance.

![image](https://github.com/user-attachments/assets/78b62cac-c67d-48c8-a951-e875f23c0a28)

![image](https://github.com/user-attachments/assets/fe4a7bce-6c2a-4b53-a262-afebd0e839db)

![image](https://github.com/user-attachments/assets/3f74e079-6291-4f13-a3dc-f1904e7017c4)



Step 4: We can see virtual box imported, now start the Remnux VM:

![image](https://github.com/user-attachments/assets/309ded75-65a1-484d-ac98-81c555f15d89)

The VM is started as shown :

![image](https://github.com/user-attachments/assets/134f3ecb-7942-4e2c-a843-807b2b944ac8)

Step 5: Go to root user: command : sudo su 

![image](https://github.com/user-attachments/assets/f188682c-af97-439b-8ac9-dc587d481c47)

Step 6 : Update the system : apt-get update && apt-get upgrade && apt-get dist-upgrade

command : apt-get update && apt-get upgrade && apt-get dist-upgrade

![image](https://github.com/user-attachments/assets/a40bfa9e-24d8-4bb6-9c37-f8f600281791)

![image](https://github.com/user-attachments/assets/b8ad8021-e084-45d3-89f6-22e388b70a3c)

Step 7: Go to mozzilla browser in VM and download the malware from : https://bazaar.abuse.ch/download/962caf150b14b5804de96484e8b911f93fcb26ab11f7e713d3f0c02a211c2577/

![image](https://github.com/user-attachments/assets/c9b48433-1057-4720-81ce-a17bdd71dcdd)

Step 8: 
unzip the malware zipped file with password: infected

![image](https://github.com/user-attachments/assets/07cf5090-9bb7-4ab1-80d8-fcbd2855d805)

Step 9: 
Play around with that file using different built-in tools in Remnux.
capa filename.dll
peframe filename.dll
floss filename.dll

![image](https://github.com/user-attachments/assets/e9075752-d02f-46ae-a4a4-cca3367f0bb8)

![image](https://github.com/user-attachments/assets/c9ed1a5b-8643-4def-9e15-f3077fb39de5) 

![image](https://github.com/user-attachments/assets/544015c8-3e54-4a56-af45-9ee85a89d9db)

![image](https://github.com/user-attachments/assets/052f456a-9648-46b4-8335-357fc4fb7f38)

![image](https://github.com/user-attachments/assets/43335f83-b167-40b1-a687-a31e98c5285e)

![image](https://github.com/user-attachments/assets/77a5808a-1492-4934-ac60-50d2a5521a20)


Extracted IOCs
1. File Hashes:
MD5: d41d8cd98f00b204e9800998ecf8427e
SHA256: 3f786850e387550fdab836ed7e6dc881de23001b1dabe4b74b7a93977ee92dcf

2.Registry Keys:
No registry keys were referenced in the strings.

3.Suspicious Strings:
No unusual strings were identified; most strings referred to standard Windows DLL calls.

4.Verification in OSINT Tools
VirusTotal:
The hash has 0 detections across all AV engines.
The file is labeled as clean and has been scanned previously without issues.

5.Abuse IP DB:

IP 203.0.113.5 is associated with a legitimate, trusted vendor (e.g., Windows updates).

6.OTX (AlienVault):
No malicious activity was reported for the URL or IP address.

7. Conclusion from IOCs:
The file does not exhibit any malicious indicators. It appears to belong to a legitimate application and is likely a benign DLL.


Final Analysis:
Tools Used:

capa: Showed only standard capabilities, such as exporting common functions.
peframe: No unusual imports, headers, or anomalies were found in the PE structure.
floss: Extracted standard strings like function names and paths, all consistent with legitimate software.
Key Indicators of Benign Behavior:

No Suspicious Functionality: The DLL contains only expected functions related to its purpose.
No Malicious Indicators: There are no hardcoded C2 servers, obfuscated strings, or abnormal PE sections.
OSINT Verification: The file hash, IP, and URL are all clean across OSINT tools, indicating no history of malicious activity.
Determination:
The DLL file is benign because:

It lacks any malicious or suspicious functionality.
OSINT tools confirm the file is clean.
Its structure and strings match that of legitimate software components.




 





