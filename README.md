Share
===

Have you ever wanted to share some files with a buddy on your lan, and had to go through all sorts of hassle to get that working?

Share is a simple cli binary that will create a file server in the current directory so that you can share your files, and close down the server quickly.

Install
---

To install make sure you have go installed, then it's as easy as getting this library:

	go get github.com/murphysean/share
	
### Sharing

Let's say you have some code you want to show your buddy in your workspace:

	cd workspace/code
	share
	
This will spin up a file server in that directory and tell you how your buddy can connect.

You can also customize the listing interface and port

	share -h 192.168.1.5 -p 8080
	share -p 8080
	
And finally you can put in the directory you wish to share

	share ../someotherdir
	share /home/sean

### Usage
	share [--host host][--port port] [dir]
	share [-h host] [-p port] [dir]

* host: Host is really the interface to bind to for listing. Defaults to all ("").
* port: The port to serve on. Defaults to an os assigned free port ("0").
* dir: The directory to serve from. Defaults to the current working directory.