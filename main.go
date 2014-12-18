package main

import (
	"flag"
	"fmt"
	"github.com/murphysean/share/advancedhttp"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
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

	//TODO Look for a config file in the home directory, or in the current directory for config (current dir overrides)
	//TODO Look for env variables
	//TODO Allow user/pass params to semi-secure requests
	//TODO Allow a switch to determine to serve via http or https(with self signed)

	var listner net.Listener
	var err error

	//TODO Hostname doesn't always mean that someone can connect via hn. Get IP instead?

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

	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	fmt.Println("PATH: ", path)
	middleman := new(Middle)
	middleman.handler = http.FileServer(http.Dir(path))
	http.Handle("/", middleman)

	//TODO Support WebDAV so that you can fire up an http git server
	//http.Handle("/", webdav.NewWebDAV(memfs.NewMemFS()))

	//http.Handle("/", http.FileServer(http.Dir(path)))
	http.HandleFunc("/upload.html", func(w http.ResponseWriter, r *http.Request) {
		rww := &advancedhttp.ResponseWriter{w, false, true, "", 0, http.StatusOK}
		defer rww.Log(r, "")
		if r.Method == "GET" {
			fmt.Fprintf(rww, `<html><title>Upload</title><body><form action="/" method="post" enctype="multipart/form-data"><label for="file">Filenames:</label><input id="file" type="file" name="file" multiple><input type="submit" name="submit" value="Submit"></form></body></html>`)
		}
	})

	fmt.Println("Serving on:", net.JoinHostPort(hostname, port))
	fmt.Println("To Serve a git repository:")
	fmt.Println("\tmv hooks/post-update.sample hooks/post-update")
	fmt.Println("\tchmod a+x hooks/post-update")
	fmt.Println("\tgit update-server-info")
	fmt.Println("Files can be uploaded via curl or html:")
	fmt.Println("\tcurl --form \"file=@filename.txt\" " + net.JoinHostPort(hostname, port))
	fmt.Println("\tvist /upload.html")
	fmt.Println("Press ctrl-c to stop sharing")
	err = http.Serve(listner, nil)
}

type Middle struct {
	handler http.Handler
}

func (m *Middle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rww := &advancedhttp.ResponseWriter{w, false, true, "", 0, http.StatusOK}
	defer rww.Log(r, "")
	if r.Method == "POST" {
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Error(rww, "POST is allowed on directories only", http.StatusBadRequest)
			return
		}

		var successString string = ""
		reader, err := r.MultipartReader()
		if err != nil {
			http.Error(rww, err.Error(), http.StatusInternalServerError)
			return
		}
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				http.Error(rww, err.Error(), http.StatusInternalServerError)
				return
			}
			if part.FileName() != "" {
				file, err := os.Create(path[:len(path)-1] + r.URL.Path + part.FileName())
				defer file.Close()
				if err != nil {
					http.Error(rww, err.Error(), http.StatusInternalServerError)
					return
				}

				size, err := io.Copy(file, part)
				if err != nil {
					http.Error(rww, err.Error(), http.StatusInternalServerError)
					return
				}
				successString += fmt.Sprintf("Created: %v, Size: %v bytes\n", part.FileName(), size)
			}
			part.Close()
		}
		rww.WriteHeader(http.StatusCreated)
		rww.Write([]byte(successString))
		return
	}

	m.handler.ServeHTTP(rww, r)
}
