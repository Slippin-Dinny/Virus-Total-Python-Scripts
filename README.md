# Virus-Total-Python-Tools

A small collection of python scripts that i've written that uses the VirusTotal API to assist in Web Security.

**Auto URL/IP Scanner:** Python script that takes in a list of URL/IP's and a API key, the script runs those URL/IP's through the Virus Total API and outputs the response to a .TXT file with how suspicious they were determined to be.

# Limits
The Virus Total API while useful doesnt come without drawbacks, without a premium API key you'll encounter limits in the amount of request's that you can proccess.
```
Request Limit - 4 Requests / min
Daily Request Quota - 500 Requests / day
Monthly Request Quota - 15,500 Requests / month
```
While using a basic free API key you'll be bound by the above limitations.
