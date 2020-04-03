# Ragno (Eng. Spider); Pron: Rah-nio.
## Ragno: IOC Multiplier
### Cast a wide net using a single IOC and extract IOC for the entire campaign
![Ragno Logo](/images/1.png)

**Introducing Ragno: IOC Multiplier**

```TL;DR: Use this Python tool to take one IOC (IP only in this first release) and expand that to all IOC related to it, download the entire list from VT and then block these to neutralise the entire campaign (or get very close to it).```

*Ragno uses Virustotal API to interact with the popular OSINT platform.*

Just like a spider, this tool launches *'webs'* which are searches based on the the IOC you provide. Each web has a potential of returning multiple results and this is how we end up with an exhaustive list of IOC that can be used to contain an entire malware campaign. 

The idea behind Ragno is to rapidly respond to an active Malware campaign by extracting a single IOC (network-based) and then use that to very quickly expand from there and get the network-infrastructure for the entire campaign so that you can block those IOC at your network perimeter and make sure there is no successful execution of the malware inside your network. Most of these malware campaign rely on a connection back to the C2 for the configuration download and in some cases for further downloads of other malicious files. If you can block a majority of these IOC on your network perimeter, the chances of the campaign hitting your network are greatly reduced. 

Please note that this tool relies on OSINT available from VT and cannot to relied on for a complete list of IOC for every single malware campaign but should be used as a rapid response tool to get as many IOC within a matter of a few seconds as possible. 

*You'll need Python 3 to run Ragno. *

## Configuring Ragno
This is a very simple step. Just open 'ragno.conf' and enter your VT API key. 
![Image](/images/2.png)

## Launch Ragno
After you have downloaded the code from GitHub, simply run the main file:
![Image](/images/3.png)

## Usage
Again, Ragno is a very easy and simple tool when it comes to usage. Simply enter the IP you have (from dynamic analysis, PCAP, sandboxing or even from VT) and follow instructions. I have configured Ragno to cast 10 webs for each search. Each web has a potential of returning results from anywhere between 1 to 100. So you can see how quickly the list can expand once you start casting the webs. 

![Image](/images/4.png)

We'll use an example I took from a recent malware campaign:

![Image](/images/5.png)

Hit Enter and then select an option:

![Image](/images/6.png)

## Communication Files: 
Files that communicate with the IP address. We will expand this section to 10 levels and then extract all the network infrastructure information we can use to build out our campaign IOC list. Please note that you will not always get all 10 levels, it really depends on how much OSINT is available on your search. 

![Image](/images/7.png)

As you can see from the screenshot above, some of our webs have returned with results and we can now start building our list. This happens in the next step.

![Image](/images/8.png)

Ragno creates a text file with all the IOC extracted and reformats it an easy-to-read manner. 'IOC-list-communicating.txt' will have all the IOC and the list is ready to use now. 

You can also print the entire list to screen by selecting option 1 from the presented menu:

![Image](/images/9.png)

As you can see above, we have been able to extract a long list of IPs associated to our initial search. In this example, the entire network-list is more than 200 IPs, which are all verified as 'malicious' on VT and can be blocked based on this OSINT report. 

The entire operation tool less than a minute :)
## Downloaded Files: 
Files downloaded from the IP address. Again, we will try to expand it to 10 levels and get all the file names that have been associated to this IOC. This will help us build out our malicious file name database which can be used to block files on the endpoints or for detection purposes. Again, don't expect all 10 webs to come back with results in all searches. 

Let's take a look at the same IP from the above example for this purpose:

![Image](/images/10.png)

Now let's take a look at the re-formated version:

![Image](/images/11.png)


There you have it. The entire list of IPs for the campaign and a comprehensive list of malware and other file names that have been associated with this IP. 

You can keep expanding the list more by going after individual IPs from the list and further expanding them but at some point you'll notice duplication of IOC in you list as infrastructure resources are limited for the actors running the campaign. 
This is the first release, I'll keep adding more features and functions to it. 

**Please feel free to use it, share it and fork it!**

*Report all problems/bugs through 'Issues' on this Repo. *

Thanks!
