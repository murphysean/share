package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"code.google.com/p/go-uuid/uuid"
	"github.com/AaronO/go-git-http"
	"github.com/murphysean/advhttp"
	"github.com/murphysean/share/extn"
)

const (
	ENVIRONMENT_VAR_HTTP_PORT  = "SHARE_HTTP_PORT"
	ENVIRONMENT_VAR_HTTPS_PORT = "SHARE_HTTPS_PORT"
	ENVIRONMENT_VAR_CERT_PATH  = "SHARE_CERT_PATH"
	ENVIRONMENT_VAR_KEY_PATH   = "SHARE_KEY_PATH"
	ENVIRONMENT_VAR_USERNAME   = "SHARE_USERNAME"
	ENVIRONMENT_VAR_PASSWORD   = "SHARE_PASSWORD"

	DEFAULT_FLAG_HTTP_PORT  = "0"
	DEFAULT_FLAG_HTTPS_PORT = ""
	DEFAULT_FLAG_CERT_PATH  = "cert.pem"
	DEFAULT_FLAG_KEY_PATH   = "key.pem"
	DEFAULT_FLAG_USERNAME   = ""
	DEFAULT_FLAG_PASSWORD   = ""

	VERSION = "1.2.0"
)

var (
	host      = ""
	port      = ""
	path      = ""
	httpPort  = flag.String("http", DEFAULT_FLAG_HTTP_PORT, "Specify the listening port for HTTP traffic. 0 = system assigned.")
	httpsPort = flag.String("https", DEFAULT_FLAG_HTTPS_PORT, "Specify the listening port for HTTPS traffic. 0 = system assigned.")
	certPath  = flag.String("cert", DEFAULT_FLAG_CERT_PATH, "Specify the path to the cert file")
	keyPath   = flag.String("key", DEFAULT_FLAG_KEY_PATH, "Specify the path to the key file")
	username  = flag.String("username", DEFAULT_FLAG_USERNAME, "Set a required username for requesting clients")
	password  = flag.String("password", DEFAULT_FLAG_PASSWORD, "Set a required password for requesting clients")
)

func init() {
	flag.StringVar(httpPort, "p", DEFAULT_FLAG_HTTP_PORT, "Short version of http port")
}

func main() {
	var err error
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s v%s:\n", os.Args[0], VERSION)
		fmt.Fprintln(os.Stderr, "share [-p|-http <http-port>] [-https <https-port>]")
		fmt.Fprintln(os.Stderr, "\t[-cert <path-to-pem>] [-key <path-to-pem>]")
		fmt.Fprintln(os.Stderr, "\t[-username <username>] [-password <password>]")
		fmt.Fprintln(os.Stderr, "\t[directory path|'help']")
		fmt.Fprintln(os.Stderr, "")
		flag.PrintDefaults()

		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintf(os.Stderr, "As an alternative to flags, use the environment variables \n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n",
			[]interface{}{ENVIRONMENT_VAR_HTTP_PORT, ENVIRONMENT_VAR_HTTPS_PORT,
				ENVIRONMENT_VAR_CERT_PATH, ENVIRONMENT_VAR_KEY_PATH,
				ENVIRONMENT_VAR_USERNAME, ENVIRONMENT_VAR_PASSWORD}...)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "You can also keep these environment variables in a file called")
		fmt.Fprintln(os.Stderr, "\t.share in your home directory, and/or the directory in which")
		fmt.Fprintln(os.Stderr, "\tyou plan to run share to persist the configuration.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Want to serve via https? Create your certificate:")
		fmt.Fprintln(os.Stderr, "---")
		fmt.Fprintln(os.Stderr, "openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem")
		fmt.Fprintln(os.Stderr, "---")
		fmt.Fprintln(os.Stderr, "\tPut them in a directory other than the one you are sharing")
		fmt.Fprintln(os.Stderr, "\tUse the -key and -cert command line flags to tell share where they are")
		fmt.Fprintln(os.Stderr, "\tStart share and specify an https port using the options above")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "To Serve a git repository directory over http:")
		fmt.Fprintln(os.Stderr, "\tmv hooks/post-update.sample hooks/post-update")
		fmt.Fprintln(os.Stderr, "\tchmod a+x hooks/post-update")
		fmt.Fprintln(os.Stderr, "\tgit update-server-info")
	}
	flag.Parse()
	log.SetFlags(0)

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

	//Look for a config file in the home directory, or in the current directory for config (current dir overrides)
	config := make(map[string]string)
	//Start with the home directory config
	if usr, err := user.Current(); err == nil {
		if _, err := os.Stat(filepath.Join(usr.HomeDir, "/.share")); !os.IsNotExist(err) {
			config = readConfig(config, filepath.Join(usr.HomeDir, "/.share"))
		}
	}
	//Now load overtop the path's config
	if _, err = os.Stat(filepath.Join(path, "/.share")); !os.IsNotExist(err) {
		config = readConfig(config, filepath.Join(path+".share"))
	}

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
	if *username == DEFAULT_FLAG_USERNAME && os.Getenv(ENVIRONMENT_VAR_USERNAME) != "" {
		flag.Set("username", os.Getenv(ENVIRONMENT_VAR_USERNAME))
	} else if *username == DEFAULT_FLAG_USERNAME && config[ENVIRONMENT_VAR_USERNAME] != "" {
		flag.Set("username", config[ENVIRONMENT_VAR_USERNAME])
	}
	if *password == DEFAULT_FLAG_PASSWORD && os.Getenv(ENVIRONMENT_VAR_PASSWORD) != "" {
		flag.Set("password", os.Getenv(ENVIRONMENT_VAR_PASSWORD))
	} else if *password == DEFAULT_FLAG_PASSWORD && config[ENVIRONMENT_VAR_PASSWORD] != "" {
		flag.Set("password", config[ENVIRONMENT_VAR_PASSWORD])
	}

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

	fmt.Fprintln(os.Stderr, "Share Server\tVersion "+VERSION)
	runtime.GOMAXPROCS(runtime.NumCPU())
	fmt.Fprintf(os.Stderr, "GOMAXPROCS=%v\n", runtime.NumCPU())
	serverProtocol := "http"
	if *httpsPort != DEFAULT_FLAG_HTTPS_PORT {
		serverProtocol = "https"
	}
	fmt.Fprintln(os.Stderr, "Serving "+serverProtocol+" on:")
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
	err = nil

	if *username != "" && *password != "" {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "User/Pass Required:")
		fmt.Fprintln(os.Stderr, "\tUsername: "+*username)
		fmt.Fprintln(os.Stderr, "\tPassword: "+*password)
		fmt.Fprintln(os.Stderr, "\tcurl -u "+*username+":"+*password)
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Directories can be downloaded:")
	fmt.Fprintln(os.Stderr, "\t Visit /targz on any directory")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Files can be uploaded:")
	fmt.Fprintln(os.Stderr, "\tcurl --form \"file=@filename.txt\" "+serverProtocol+"://"+net.JoinHostPort(hostname, port)+"/")
	fmt.Fprintln(os.Stderr, "\tcurl --data \"file=@filename.txt\" -H \"Content-Type: text/plain\" "+serverProtocol+"://"+net.JoinHostPort(hostname, port)+"/")
	fmt.Fprintln(os.Stderr, "\tcurl -X PUT --data @filename.txt "+serverProtocol+"://"+net.JoinHostPort(hostname, port)+"/filename.txt")
	fmt.Fprintln(os.Stderr, "\tVisit /upload.html on any directory")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "If the directory is a git repository (working or bare):")
	fmt.Fprintln(os.Stderr, "\tgit clone "+serverProtocol+"://"+net.JoinHostPort(hostname, port))
	fmt.Fprintln(os.Stderr, "\tThere is also support for git push")
	fmt.Fprintln(os.Stderr, "\tgit push")
	fmt.Fprintln(os.Stderr, "")
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

func logApache(w *advhttp.ResponseWriter, r *http.Request) {
	log.Println(advhttp.LogApache(w, r))
}

func (m *Middle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rww := advhttp.NewResponseWriter(w)
	//Put in a header that says this was share that served the content
	rww.Header().Set("Server", "Share/"+VERSION)
	rww.Header().Set("X-Powered-By", runtime.Version())
	defer logApache(rww, r)

	//If username and password required, check for credentials from the user, and prompt for them if not provided
	if *username != "" && *password != "" {
		if u, p, ok := r.BasicAuth(); ok {
			if u != *username || p != *password {
				rww.Header().Set("WWW-Authenticate", `Basic realm="share"`)
				http.Error(rww, "Not Authorized", http.StatusUnauthorized)
				return
			}
			r.Header.Set("User-Id", u)
		} else {
			rww.Header().Set("WWW-Authenticate", `Basic realm="share"`)
			http.Error(rww, "Not Authorized", http.StatusUnauthorized)
			return
		}
	}

	if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/targz") {
		if _, err := os.Stat(filepath.Join(path, r.URL.Path)); !os.IsNotExist(err) {
			http.Error(rww, "Not Found", http.StatusNotFound)
			return
		}
		filename := strings.Replace(filepath.Dir(r.URL.Path), "/", "-", -1)
		filename = filename[1:]
		if filename == "" {
			filename = "root"
		}
		filename += ".tar.gz"
		rww.Header().Set("Content-Type", "application/x-tar")
		rww.Header().Set("Content-Encoding", "gzip")
		rww.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")

		gw := gzip.NewWriter(rww)
		defer gw.Close()

		tw := tar.NewWriter(gw)
		defer tw.Close()

		// tar bytes -> gzip bytes -> rww bytes
		filepath.Walk(filepath.Join(path, filepath.Dir(r.URL.Path)), func(p string, info os.FileInfo, err error) error {
			if info.Mode().IsDir() && strings.Contains(p, "/.git") {
				return filepath.SkipDir
			}
			if info.Mode().IsDir() {
				return nil
			}
			new_path := p[len(path):]
			if len(new_path) == 0 {
				return nil
			}
			fr, err := os.Open(p)
			if err != nil {
				return err
			}
			defer fr.Close()

			if h, err := tar.FileInfoHeader(info, new_path); err != nil {
				//log.Fatalln(err)
				return err
			} else {
				h.Name = new_path
				if err = tw.WriteHeader(h); err != nil {
					//log.Fatalln(err)
					return err
				}
			}
			if _, err := io.Copy(tw, fr); err != nil {
				//log.Fatalln(err)
				return err
			}
			return nil
		})
		return
	}

	if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/upload.html") {
		fmt.Fprintf(rww, `<html><title>Upload</title><body><form action="./" method="post" enctype="multipart/form-data"><label for="file">Filenames:</label><input id="file" type="file" name="file" multiple><input type="submit" name="submit" value="Submit"></form></body></html>`)
		return
	}

	//See if this is a git request
	if isGitRequest(r.URL.Path) {
		m.git.ServeHTTP(rww, r)
		return
	}

	if r.Method == "POST" {
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Error(rww, "POST is allowed on directories only", http.StatusNotFound)
			return
		}
		var successString string = ""
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && mt == "multipart/form-data" {
			os.MkdirAll(filepath.Dir(path)+r.URL.Path, 0775)
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
					os.MkdirAll(path[:len(path)-1]+r.URL.Path, 0775)
					file, err := os.Create(filepath.Dir(path) + r.URL.Path + part.FileName())
					if err != nil {
						http.Error(rww, err.Error(), http.StatusInternalServerError)
						return
					}
					defer file.Close()

					size, err := io.Copy(file, part)
					if err != nil {
						http.Error(rww, err.Error(), http.StatusInternalServerError)
						return
					}
					rww.Header().Add("Location", r.URL.Path+part.FileName())
					successString += fmt.Sprintf("Created: %v, Size: %v bytes\n", part.FileName(), size)
				}
				part.Close()
			}
		} else {
			if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && mt != "" {
				os.MkdirAll(filepath.Dir(path)+r.URL.Path, 0775)
				extension := extn.GetExtensionForMime(mt)
				if extension == "" {
					http.Error(rww, "Content-Type not Understood", http.StatusUnsupportedMediaType)
					return
				}
				filename := uuid.New() + extension
				file, err := os.Create(filepath.Dir(path) + r.URL.Path + filename)
				if err != nil {
					http.Error(rww, err.Error(), http.StatusInternalServerError)
					return
				}
				defer file.Close()

				size, err := io.Copy(file, r.Body)
				if err != nil {
					http.Error(rww, err.Error(), http.StatusInternalServerError)
					return
				}
				rww.Header().Set("Location", r.URL.Path+filename)
				successString = fmt.Sprintf("Created: %v, Size: %v bytes\n", filename, size)
			} else {
				http.Error(rww, "Need a valid Content-Type header", http.StatusUnsupportedMediaType)
				return
			}
		}
		rww.WriteHeader(http.StatusCreated)
		rww.Write([]byte(successString))
		return
	}

	if r.Method == "PUT" {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.Error(rww, "PUT is allowed on files only", http.StatusNotFound)
			return
		}
		//Need to strip the file off the path
		os.MkdirAll(filepath.Dir(path)+filepath.Dir(r.URL.Path), 0775)

		file, err := os.Create(filepath.Dir(path) + r.URL.Path)
		if err != nil {
			http.Error(rww, err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = io.Copy(file, r.Body)
		if err != nil {
			http.Error(rww, err.Error(), http.StatusInternalServerError)
			return
		}

		rww.WriteHeader(http.StatusCreated)
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

func readConfig(inconfig map[string]string, path string) (ret map[string]string) {
	ret = inconfig
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
