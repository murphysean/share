package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
)

var hostname string
var host string
var port string
var path string

func init() {
	flag.StringVar(&host, "host", "", "The interface to bind to")
	flag.StringVar(&host, "h", "", "The interface to bind to")
	flag.StringVar(&port, "port", "0", "The port to bind to")
	flag.StringVar(&port, "p", "0", "The port to bind to")
}

func main() {
	flag.Parse()
	var listner net.Listener
	var err error
	//Get the Hostname of the machine
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println(err)
		return
	}
	//Get an open port on the machine
	if net.JoinHostPort(host, port) == ":0" {
		listner, err = net.Listen("tcp", ":0")
	} else {
		listner, err = net.Listen("tcp", net.JoinHostPort(host, port))
	}
	if err != nil {
		fmt.Println(err)
		return
	}

	_, port, err = net.SplitHostPort(listner.Addr().String())
	if err != nil {
		fmt.Println(err)
		return
	}

	//Get the Working Directory
	path, err = os.Getwd()
	if err != nil {
		fmt.Println(err)
		return
	}

	//Get the file/dir to be shared from the path (if none specified, utilize the pwd)
	if flag.Arg(0) != "" {
		path = flag.Arg(0)
		stat, err := os.Stat(path)
		if os.IsNotExist(err) {
			fmt.Println(err)
			return
		}

		if !stat.IsDir() {
			fmt.Println(fmt.Errorf("Provided path must be a directory"))
			return
		}
	}

	fmt.Println("Serving on:", net.JoinHostPort(hostname, port))
	fmt.Println("Press ctrl-c to stop sharing")
	err = http.Serve(listner, http.FileServer(http.Dir(path)))
}
