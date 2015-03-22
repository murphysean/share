package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/AaronO/go-git-http"
	"github.com/murphysean/share/advancedhttp"
)

const (
	ENVIRONMENT_VAR_HTTP_PORT      = "HTTP_PORT"
	ENVIRONMENT_VAR_HTTPS_PORT     = "HTTPS_PORT"
	ENVIRONMENT_VAR_CERT_PATH      = "CERT_PATH"
	ENVIRONMENT_VAR_KEY_PATH       = "KEY_PATH"
	ENVIRONMENT_VAR_SHARE_USERNAME = "SHARE_USERNAME"
	ENVIRONMENT_VAR_SHARE_PASSWORD = "SHARE_PASSWORD"
	DEFAULT_FLAG_HTTP_PORT         = "0"
	DEFAULT_FLAG_HTTPS_PORT        = ""
	DEFAULT_FLAG_CERT_PATH         = "cert.pem"
	DEFAULT_FLAG_KEY_PATH          = "key.pem"
	DEFAULT_FLAG_SHARE_USERNAME    = ""
	DEFAULT_FLAG_SHARE_PASSWORD    = ""
)

var (
	host      = ""
	port      = ""
	path      = ""
	httpPort  = flag.String("http", DEFAULT_FLAG_HTTP_PORT, "Specify the listening port for HTTP traffic")
	httpsPort = flag.String("https", DEFAULT_FLAG_HTTPS_PORT, "Specify the listening port for HTTPS traffic")
	certPath  = flag.String("cert", DEFAULT_FLAG_CERT_PATH, "Specify the path to the cert file")
	keyPath   = flag.String("key", DEFAULT_FLAG_KEY_PATH, "Specify the path to the key file")
	username  = flag.String("username", DEFAULT_FLAG_SHARE_USERNAME, "Set a required username for requesting clients")
	password  = flag.String("password", DEFAULT_FLAG_SHARE_PASSWORD, "Set a required password for requesting clients")
)

func init() {
	flag.StringVar(httpPort, "p", DEFAULT_FLAG_HTTP_PORT, "Short version of http port")
}

func main() {
	var err error
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "share [-h] [-p|-http <http-port>] [-https <https-port>]")
		fmt.Fprintln(os.Stderr, "\t[-cert <path-to-pem>] [-key <path-to-pem>]")
		fmt.Fprintln(os.Stderr, "\t[-username <username>] [-password <password>]")
		fmt.Fprintln(os.Stderr, "\t[directory path]")
		flag.PrintDefaults()

		fmt.Fprintf(os.Stderr, "type help for help\n")
		fmt.Fprintf(os.Stderr, "As an alternative to flags, use the environment variables %s, %s, %s, %s, %s and %s\n",
			[]interface{}{ENVIRONMENT_VAR_HTTP_PORT, ENVIRONMENT_VAR_HTTPS_PORT,
				ENVIRONMENT_VAR_CERT_PATH, ENVIRONMENT_VAR_KEY_PATH,
				ENVIRONMENT_VAR_SHARE_USERNAME, ENVIRONMENT_VAR_SHARE_PASSWORD})
		fmt.Fprintf(os.Stderr, "You can also keep these environment variables in a file called .share in your directory to persist the configuration\n")
	}
	flag.Parse()
	log.SetFlags(0)

	//Look for a config file in the home directory, or in the current directory for config (current dir overrides)
	config := readConfig(path + ".share")

	//Look for env variables
	if *httpPort == DEFAULT_FLAG_HTTP_PORT && os.Getenv(ENVIRONMENT_VAR_HTTP_PORT) != "" {
		flag.Set("http", os.Getenv(ENVIRONMENT_VAR_HTTP_PORT))
	} else if *httpPort == DEFAULT_FLAG_HTTP_PORT && config[ENVIRONMENT_VAR_HTTP_PORT] != "" {
		flag.Set("http", config[ENVIRONMENT_VAR_HTTP_PORT])
	}
	if *httpsPort == DEFAULT_FLAG_HTTPS_PORT && os.Getenv(ENVIRONMENT_VAR_HTTPS_PORT) != "" {
		flag.Set("https", os.Getenv(ENVIRONMENT_VAR_HTTPS_PORT))
	} else if *httpsPort == DEFAULT_FLAG_HTTPS_PORT && config[ENVIRONMENT_VAR_HTTPS_PORT] != "" {
		flag.Set("https", config[ENVIRONMENT_VAR_HTTPS_PORT])
	}
	if *certPath == DEFAULT_FLAG_CERT_PATH && os.Getenv(ENVIRONMENT_VAR_CERT_PATH) != "" {
		flag.Set("cert", os.Getenv(ENVIRONMENT_VAR_CERT_PATH))
	} else if *certPath == DEFAULT_FLAG_CERT_PATH && config[ENVIRONMENT_VAR_CERT_PATH] != "" {
		flag.Set("cert", config[ENVIRONMENT_VAR_CERT_PATH])
	}
	if *keyPath == DEFAULT_FLAG_KEY_PATH && os.Getenv(ENVIRONMENT_VAR_KEY_PATH) != "" {
		flag.Set("key", os.Getenv(ENVIRONMENT_VAR_KEY_PATH))
	} else if *keyPath == DEFAULT_FLAG_KEY_PATH && config[ENVIRONMENT_VAR_KEY_PATH] != "" {
		flag.Set("key", config[ENVIRONMENT_VAR_KEY_PATH])
	}

	//Allow user/pass params to semi-secure requests
	if *username == DEFAULT_FLAG_SHARE_USERNAME && os.Getenv(ENVIRONMENT_VAR_SHARE_USERNAME) != "" {
		flag.Set("username", os.Getenv(ENVIRONMENT_VAR_SHARE_USERNAME))
	} else if *username == DEFAULT_FLAG_SHARE_USERNAME && config[ENVIRONMENT_VAR_SHARE_USERNAME] != "" {
		flag.Set("username", config[ENVIRONMENT_VAR_SHARE_USERNAME])
	}
	if *password == DEFAULT_FLAG_SHARE_PASSWORD && os.Getenv(ENVIRONMENT_VAR_SHARE_PASSWORD) != "" {
		flag.Set("password", os.Getenv(ENVIRONMENT_VAR_SHARE_PASSWORD))
	} else if *password == DEFAULT_FLAG_SHARE_PASSWORD && config[ENVIRONMENT_VAR_SHARE_PASSWORD] != "" {
		flag.Set("password", config[ENVIRONMENT_VAR_SHARE_PASSWORD])
	}

	if flag.Arg(0) == "help" {
		flag.Usage()
		return
	}

	//Get the Working Directory
	path, err = os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	//Get the file/dir to be shared from the path (if none specified, utilize the pwd)
	if flag.Arg(0) != "" {
		path = flag.Arg(0)
		stat, err := os.Stat(path)
		if os.IsNotExist(err) {
			log.Fatal(err)
		}

		if !stat.IsDir() {
			log.Fatal(fmt.Errorf("Provided path must be a directory"))
		}
	}

	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	fmt.Println("Sharing:", path)

	//Get the Hostname of the machine
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal(err)
	}

	if *httpsPort != DEFAULT_FLAG_HTTPS_PORT {
		port = *httpsPort
	} else if *httpPort != DEFAULT_FLAG_HTTP_PORT {
		port = *httpPort
	} else {
		port = "0"
	}
	var listner net.Listener
	listner, err = net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		log.Fatal(err)
	}

	_, port, err = net.SplitHostPort(listner.Addr().String())
	if err != nil {
		log.Fatal(err)
	}

	middleman := new(Middle)
	middleman.file = http.FileServer(http.Dir(path))
	//Set up a .git handler
	githandler := githttp.New(path)
	githandler.EventHandler = func(githttp.Event) {
		//Do Nothing
	}
	middleman.git = githandler
	http.Handle("/", middleman)

	http.HandleFunc("/upload.html", func(w http.ResponseWriter, r *http.Request) {
		rww := &advancedhttp.ResponseWriter{w, false, true, "", 0, http.StatusOK}
		defer rww.Log(r, "")
		if r.Method == "GET" {
			fmt.Fprintf(rww, `<html><title>Upload</title><body><form action="/" method="post" enctype="multipart/form-data"><label for="file">Filenames:</label><input id="file" type="file" name="file" multiple><input type="submit" name="submit" value="Submit"></form></body></html>`)
		}
	})

	fmt.Fprintln(os.Stderr, "Serving on:")
	fmt.Fprintln(os.Stderr, "\thost\t"+net.JoinHostPort(hostname, port))
	out, err := exec.Command("ip", "-4", "addr", "show").Output()
	if err == nil {
		re := regexp.MustCompile(`(?m)inet ([0-9].*)\/.*(\b.*[0-9])$`)
		vs := re.FindAllStringSubmatch(string(out), -1)
		for _, as := range vs {
			if len(as) == 3 {
				fmt.Fprintln(os.Stderr, "\t"+as[2]+"\t"+net.JoinHostPort(as[1], port))
			}
		}
	}
	fmt.Fprintln(os.Stderr, "To Serve a git repository:")
	fmt.Fprintln(os.Stderr, "\tmv hooks/post-update.sample hooks/post-update")
	fmt.Fprintln(os.Stderr, "\tchmod a+x hooks/post-update")
	fmt.Fprintln(os.Stderr, "\tgit update-server-info")
	fmt.Fprintln(os.Stderr, "Files can be uploaded via curl or html:")
	fmt.Fprintln(os.Stderr, "\tcurl --form \"file=@filename.txt\" "+net.JoinHostPort(hostname, *httpPort))
	fmt.Fprintln(os.Stderr, "\tvisit /upload.html")
	if *httpsPort == DEFAULT_FLAG_HTTPS_PORT {
		fmt.Fprintln(os.Stderr, "Want to serve via https? Create your certificate")
		fmt.Fprintln(os.Stderr, "\topenssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem")
		fmt.Fprintln(os.Stderr, "\tPut them in a directory other than the one you are sharing")
		fmt.Fprintln(os.Stderr, "\tUse the -key and -cert command line flags to tell share where they are")
	}
	fmt.Fprintln(os.Stderr, "Press ctrl-c to stop sharing")

	if *httpsPort != DEFAULT_FLAG_HTTPS_PORT {
		certificate, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			log.Fatal(err)
		}

		config := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS10}
		tlsListener := tls.NewListener(listner, config)

		log.Fatal(http.Serve(tlsListener, nil))
	} else {
		log.Fatal(http.Serve(listner, nil))
	}
}

type Middle struct {
	file http.Handler
	git  http.Handler
}

func (m *Middle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rww := &advancedhttp.ResponseWriter{w, false, true, "", 0, http.StatusOK}
	defer rww.Log(r, "")

	//If username and password required, check for credentials from the user, and prompt for them if not provided
	if *username != "" && *password != "" {
		if u, p, ok := r.BasicAuth(); ok {
			if u != *username || p != *password {
				rww.Header().Set("WWW-Authenticate", `Basic realm="share"`)
				http.Error(rww, "Not Authorized", http.StatusUnauthorized)
				return
			}
		} else {
			rww.Header().Set("WWW-Authenticate", `Basic realm="share"`)
			http.Error(rww, "Not Authorized", http.StatusUnauthorized)
			return
		}
	}

	//See if this is a git request
	if isGitRequest(r.URL.Path) {
		m.git.ServeHTTP(rww, r)
		return
	}

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

	m.file.ServeHTTP(rww, r)
}

func isGitRequest(path string) bool {
	serviceRpcUpload := regexp.MustCompile("(.*?)/git-upload-pack$")
	serviceRpcReceive := regexp.MustCompile("(.*?)/git-receive-pack$")
	getInfoRefs := regexp.MustCompile("(.*?)/info/refs$")
	getHead := regexp.MustCompile("(.*?)/HEAD$")
	getAlternates := regexp.MustCompile("(.*?)/objects/info/alternates$")
	getHttpAlternates := regexp.MustCompile("(.*?)/objects/info/http-alternates$")
	getInfoPacks := regexp.MustCompile("(.*?)/objects/info/packs$")
	getInfoFile := regexp.MustCompile("(.*?)/objects/info/[^/]*$")
	getLooseObject := regexp.MustCompile("(.*?)/objects/[0-9a-f]{2}/[0-9a-f]{38}$")
	getPackFile := regexp.MustCompile("(.*?)/objects/pack/pack-[0-9a-f]{40}\\.pack$")
	getIdxFile := regexp.MustCompile("(.*?)/objects/pack/pack-[0-9a-f]{40}\\.idx$")

	if serviceRpcUpload.MatchString(path) || serviceRpcReceive.MatchString(path) ||
		getInfoRefs.MatchString(path) || getHead.MatchString(path) || getAlternates.MatchString(path) ||
		getHttpAlternates.MatchString(path) || getInfoPacks.MatchString(path) || getInfoFile.MatchString(path) ||
		getLooseObject.MatchString(path) || getPackFile.MatchString(path) || getIdxFile.MatchString(path) {
		return true
	}

	return false
}

func readConfig(path string) (ret map[string]string) {
	ret = make(map[string]string)
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "=")
		if len(parts) == 2 {
			ret[parts[0]] = parts[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return
	}

	return
}
