Share
===

Have you ever wanted to share some files with a buddy on your lan, and had to go through all 
sorts of hassle to get that working? Or perhaps you wonder what it would be like to actually use 
git as a distributed version control system?

Share is a simple cli binary that will create a file server in the current directory so that you 
can share your files, and close down the server quickly.

Install
---

To install make sure you have go installed, then it's as easy as getting this library:

	go get github.com/murphysean/share
	
### Sharing

Let's say you have some code you want to show your buddy in your workspace:

	cd workspace/code
	share
	
This will spin up a file server in that directory and tell you how your buddy can connect. For 
example:

	Serving http on:
		host	Prometheus:43959
		wlan0	192.168.1.14:43959
		
Notice that if you don't specify anything `share` will use a system assigned port in the high 
port range. Perhaps you'd like to use a specific port:

	share -p 8080
	
Then there are times where you'd like to serve a particular directory on the same port every 
time you fire it up. Share looks for a configuration file in the directory to be served, and 
also in your home directory. If you create `.share` in the directory with the following 
contents:

	SHARE_HTTP_PORT=8080
	SHARE_USERNAME=user
	SHARE_PASSWORD=password
	
Whenever you run `share` in that directory share will run on port 8080 (if available) and 
require authentication before serving content.

Share also comes with a 'smart' git server built in. So others can git clone, fetch, and pull 
using the same http(s) address that they can use to browse. After you `git init` your directory 
others could clone your repository like so:

	git clone http://192.168.1.3/
	
And finally you can change the directory you wish to share (default is the current directory)

	share ../someotherdir
	share /home/sean
	
### Receiving

Sharing your files is only half the fun. Sometimes you'd really like your cohorts to contribute 
something back to your directory. With a 'smart' git server built in if they had previously 
cloned from you they can push there changes back with git. For example to push a branch back up 
to the server they could:

	git push -u origin shinynewbranch
	
However sometimes you'd really just like to receive that handy little script from your mate. 
Share has a built in web-page that allows someone to use an html form to upload files. Just 
navigate to `http(s)://yourip:port/upload.html`, select a file, and upload it.

Share also allows POST and PUT verbs. So for the curl guys out there:

1. Form upload files (POST)

	`curl --form "file=@filename.txt" http(s)://host:port/`
	
2. Upload file bytes (POST)

	`curl --data "file=@filename.txt" -H "Content-Type: text/plain" http(s)://host:port/`
	
3. Put up a file (PUT)

	`curl -X PUT --data @filename.txt http(s)://host:port/filename.txt`
	
The POST call will work on any directory path (Path ends with a /) even if the directory does not yet 
exist. The PUT verb will work on any file (Path doesn't end with a /) even if the path doesn't exist 
yet.

### Usage

Type `share help` to get this information on the command line.

	Usage of share v1.1.0:
	share [-h] [-p|-http <http-port>] [-https <https-port>]
		[-cert <path-to-pem>] [-key <path-to-pem>]
		[-username <username>] [-password <password>]
		[directory path|'help']

	-cert="cert.pem": Specify the path to the cert file
	-http="0": Specify the listening port for HTTP traffic. 0 = system assigned.
	-https="": Specify the listening port for HTTPS traffic. 0 = system assigned.
	-key="key.pem": Specify the path to the key file
	-p="0": Short version of http port
	-password="": Set a required password for requesting clients
	-username="": Set a required username for requesting clients

	As an alternative to flags, use the environment variables 
		SHARE_HTTP_PORT
		SHARE_HTTPS_PORT
		SHARE_CERT_PATH
		SHARE_KEY_PATH
		SHARE_USERNAME
		SHARE_PASSWORD

	You can also keep these environment variables in a file called
		.share in your home directory, and/or the directory in which
		you plan to run share to persist the configuration.

	Want to serve via https? Create your certificate:
	---
	openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem
	---
		Put them in a directory other than the one you are sharing
		Use the -key and -cert command line flags to tell share where they are
		Start share and specify an https port using the options above

	To Serve a git repository directory over http:
		mv hooks/post-update.sample hooks/post-update
		chmod a+x hooks/post-update
		git update-server-info
