Share
===

Have you ever wanted to share some files with a buddy on your LAN, and had to go through all 
sorts of hassle to get that working? Or perhaps you wonder what it would be like to actually use 
git as a distributed version control system?

Share is a simple cli binary that will create a file server in the current directory so that you 
can share your files, and close down the server quickly.

Install
---

To install make sure you have go installed, then it's as easy as getting this library:

	go get github.com/murphysean/share

I've only tested share on ubuntu linux 64. I'd be happy if any contributors would like to 
verify or expand this to other platforms.

Run
---
	
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

	git clone http://host:port/
	
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

Share also allows POST, PUT and DELETE verbs. So for the curl guys out there:

1. Form upload files (POST)

	`curl --form "file=@filename.txt" http(s)://host:port/`
	
2. Upload file bytes (POST)

	`curl --data "file=@filename.txt" -H "Content-Type: text/plain" http(s)://host:port/`
	
3. Put up a file (PUT)

	`curl -X PUT --data @filename.txt http(s)://host:port/filename.txt`
	
4. Delete a file on the server (DELETE)

	`curl -X DELETE http(s)://host:port/filename.txt`
	
The POST call will work on any directory path (Path ends with a /) even if the directory does not yet 
exist. The PUT verb will work on any file (Path doesn't end with a /) even if the path doesn't exist 
yet. Finally the DELETE verb will work on any file or directory as long as it isn\'t the root 
directory.

### Authentication

Share allows you to protect your directory through http basic authorization. Since share allows 
clients to both pull (GET, HEAD), and push (POST, PUT, PATCH, DELETE), share allows you to control 
access for both of these operations. Setting the -username and -password flags will enable 
protection for both pulling and pushing clients. It will force them to use those credentials.

If you also set the -push-username and -push-password flags, the credentials for pulling clients 
will remain those set for -username and -password, but will require pushing clients to use the push 
credentials.

Finally if you only set the -push-* credentials, pulling clients will not be required to 
authenticate, but pushing clients will.

Examples:

1. `share -username sean -password sean` will require both pushing and pulling clients to 
authenticate with sean:sean.
2. `share -username -password sean -push-username git -push-password git` will require pushing 
clients to use sean:sean, and pulling clients to use git:git
3. `share push-username git -push-password git` will allow anyone to download or fetch files from 
share, but will require pushing clients to authenticate with git:git

In curl you can enable basic authentication using the -u flag. For example: 
`curl -u sean:sean http(s)://host:port/filename.txt`. In wget you can enable basic authentication 
by using the `--username` and `--password` flags. For example: 
`wget http(s)://host:port/filename.txt --user=sean --password=sean`.

### TLS/SSL and enabling secure communication to share

If you want to enable https communication to share all you'll need is to get ahold of a certificate 
file and a key file. The easiest way is to create a rsa key, and a self signed cert:

	openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem
	
You'll want to put these files somewhere that won't be shared through _share_, otherwise your 
private key used to secure traffic could be compromised.

The recommended option is to create a _.share_ file in your home directory along with your _cert.pem_ 
and your _key.pem_ files. In the share file put the full path to the _cert.pem_ and _key.pem_ files 
as the attributes to the environment variable keys. It will look something like this:

	SHARE_CERT_PATH=/home/sean/cert.pem
	SHARE_KEY_PATH=/home/sean/key.pem
	
Finally you'll just want to start share up with the `-https` command line flag, or the `SHARE_HTTPS_PORT` 
environment variable set. You can specify the port as 0 to just have share nab a system assigned port.

If you are lucky enough to have a certificate signed by a trusted certificate authority and a valid 
signing chain then clients will trust you and you'll get the nice green lock in most browsers.
However if you are just sharing over ip addresses or hostnames on a local network you'll run into 
problems with https validation in both browsers and clients.

The easiest solution to this problem is to just have those browsing your share to click the bypass 
button in their browser and "proceed unsafely". You can also do the equivalent in curl using the `-k` 
or `--insecure` flag. In wget, there is the `--no-check-certificate` flag.

Another solution is to have your buddy add your self signed cert to their certificate store, thus 
trusting any connections to your server from any client using the trust store. On ubuntu this [link][deb-cert] 
will detail how to do this. Just make sure you are setting the common name to the domain name, 
hostname or ip address of your box.
	
### Configuration
	
Share looks for configuration in a number of places as it starts up:

1. The command line flags
2. Environment variables
3. A .share file in the share directory
4. A .share file in the users home directory
5. A share.conf file at /etc/share/share.conf

Configuration settings found at the lower numbers will override those found at the higher numbers. 
Options [3-5] are basic .ini type configuration files. The keys match the environment variable keys, 
and all start with SHARE\_*. Certificates, keys, usernames and passwords are all good options to 
keep in config that will not be available through the share directory itself.

### Usage

Type `share help` to get this information on the command line.

	Usage of share v1.1.0:
	share [-h] [-p|-http <http-port>] [-https <https-port>]
		[-cert <path-to-pem>] [-key <path-to-pem>]
		[-username <username>] [-password <password>]
		[-push-username <username>] [-push-password <password>]
		[directory path|'help']

	-http="0": Specify the listening port for HTTP traffic. 0 = system assigned.
	-p="0": Short version of http port
	-https="": Specify the listening port for HTTPS traffic. 0 = system assigned.
	-cert="cert.pem": Specify the path to the cert file
	-key="key.pem": Specify the path to the key file
	-username="": Set a required username for requesting clients
	-password="": Set a required password for requesting clients
	-push-username="": Set a required username for clients pushing or uploading
	-push-password="": Set a required password for clients pushing or uploading

	As an alternative to flags, use the environment variables 
		SHARE_HTTP_PORT
		SHARE_HTTPS_PORT
		SHARE_CERT_PATH
		SHARE_KEY_PATH
		SHARE_USERNAME
		SHARE_PASSWORD
		SHARE_PUSH_USERNAME
		SHARE_PUSH_PASSWORD

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
		
### Running

Share logs to both stdout and stderr. Here's a breakdown of where information goes:

- Errors -> stderr
- Information -> stderr
- Access Logs -> stdout

Start share and only show errors and startup information:

	share > /dev/null
	
Start share and only show access logs (in apache format):

	share 2> /dev/null
	
Start share and direct all output to a file _logs.txt_:

	share > logs.txt 2>&1
	
You can also run share in the background:

	share > logs.txt 2>&1 &
	
Or have the shell disown the process:

	share > logs.txt 2>&1 & disown

Or run it as a daemon:

	nohup share > logs.txt 2>&1 &

[deb-cert]: http://superuser.com/questions/437330/how-do-you-add-a-certificate-authority-ca-to-ubuntu "Debian Trust Store"