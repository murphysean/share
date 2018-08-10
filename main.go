package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"github.com/AaronO/go-git-http"
	"github.com/murphysean/advhttp"
	"github.com/murphysean/heimdall"
	"github.com/murphysean/heimdall/memdb"
	"github.com/murphysean/share/extn"
	flag "github.com/ogier/pflag"
	"gopkg.in/russross/blackfriday.v2"
	"io"
	"io/ioutil"
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
)

const (
	ENVIRONMENT_VAR_PORT          = "SHARE_PORT"
	ENVIRONMENT_VAR_CERT_PATH     = "SHARE_CERT_PATH"
	ENVIRONMENT_VAR_KEY_PATH      = "SHARE_KEY_PATH"
	ENVIRONMENT_VAR_USERNAME      = "SHARE_USERNAME"
	ENVIRONMENT_VAR_PASSWORD      = "SHARE_PASSWORD"
	ENVIRONMENT_VAR_PUSH_USERNAME = "SHARE_PUSH_USERNAME"
	ENVIRONMENT_VAR_PUSH_PASSWORD = "SHARE_PUSH_PASSWORD"

	DEFAULT_FLAG_PORT          = "0"
	DEFAULT_FLAG_CERT_PATH     = "cert.pem"
	DEFAULT_FLAG_KEY_PATH      = "key.pem"
	DEFAULT_FLAG_USERNAME      = ""
	DEFAULT_FLAG_PASSWORD      = ""
	DEFAULT_FLAG_PUSH_USERNAME = ""
	DEFAULT_FLAG_PUSH_PASSWORD = ""

	VERSION = "1.4.1"
)

func GenUUIDv4() string {
	u := make([]byte, 16)
	rand.Read(u)
	//Set the version to 4
	u[6] = (u[6] | 0x40) & 0x4F
	u[8] = (u[8] | 0x80) & 0xBF
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:])
}

var (
	host         = ""
	path         = ""
	port         = flag.StringP("port", "p", DEFAULT_FLAG_PORT, "Specify the tcp listening port for traffic. 0 = system assigned.")
	certPath     = flag.StringP("cert", "c", DEFAULT_FLAG_CERT_PATH, "Specify the path to the cert file")
	keyPath      = flag.StringP("key", "k", DEFAULT_FLAG_KEY_PATH, "Specify the path to the key file")
	username     = flag.StringP("username", "u", DEFAULT_FLAG_USERNAME, "Set a required username for requesting clients")
	password     = flag.StringP("password", "P", DEFAULT_FLAG_PASSWORD, "Set a required password for requesting clients")
	pushUsername = flag.StringP("push-username", "a", DEFAULT_FLAG_PUSH_USERNAME, "Set a required username for clients pushing or uploading")
	pushPassword = flag.StringP("push-password", "b", DEFAULT_FLAG_PUSH_PASSWORD, "Set a required password for clients pushing or uploading")
)

func main() {
	var err error
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s v%s:\n", os.Args[0], VERSION)
		fmt.Fprintln(os.Stderr, "share [-p|-port <http-port>]")
		fmt.Fprintln(os.Stderr, "\t[-c|-cert <path-to-pem>] [-k|-key <path-to-pem>]")
		fmt.Fprintln(os.Stderr, "\t[-u|-username <username>] [-P|-password <password>]")
		fmt.Fprintln(os.Stderr, "\t[-a|-push-username <username>] [-b|-push-password <password>]")
		fmt.Fprintln(os.Stderr, "\t[directory path|'help']")
		fmt.Fprintln(os.Stderr, "")
		flag.PrintDefaults()

		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintf(os.Stderr, "As an alternative to flags, use the environment variables \n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n",
			[]interface{}{ENVIRONMENT_VAR_PORT,
				ENVIRONMENT_VAR_CERT_PATH, ENVIRONMENT_VAR_KEY_PATH,
				ENVIRONMENT_VAR_USERNAME, ENVIRONMENT_VAR_PASSWORD,
				ENVIRONMENT_VAR_PUSH_USERNAME, ENVIRONMENT_VAR_PUSH_PASSWORD}...)
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

	if flag.Arg(0) == "help" {
		flag.Usage()
		return
	}

	//Get the Working Directory
	path, err = os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	//Get the file/dir to be shared from the path (if none specified, utilize the pwd)
	if flag.Arg(0) != "" {
		path = flag.Arg(0)
		stat, err := os.Stat(path)
		if os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		if !stat.IsDir() {
			fmt.Fprintln(os.Stderr, fmt.Errorf("Provided path must be a directory"))
			os.Exit(1)
		}
	}

	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	fmt.Fprintln(os.Stderr, "Sharing:", path)

	//Look for a config file in etc, the home directory, or in the current directory for config (current dir overrides)
	config := make(map[string]string)
	//Look for a config file at /etc/share/share.conf
	if _, err := os.Stat("/etc/share/share.conf"); err == nil {
		config = readConfig(config, "/etc/share/share.conf")
		fmt.Fprintln(os.Stderr, "Read /etc/share/share.conf")
	}
	//Start with the home directory config
	if usr, err := user.Current(); err == nil {
		if _, err := os.Stat(filepath.Join(usr.HomeDir, "/.share")); !os.IsNotExist(err) {
			config = readConfig(config, filepath.Join(usr.HomeDir, "/.share"))
			fmt.Fprintln(os.Stderr, "Read "+filepath.Join(usr.HomeDir, "/.share"))
		}
	}
	//Now load overtop the path's config
	if _, err = os.Stat(filepath.Join(path, "/.share")); !os.IsNotExist(err) {
		config = readConfig(config, filepath.Join(path+".share"))
		fmt.Fprintln(os.Stderr, "Read "+filepath.Join(path+".share"))
	}

	//Look for env variables
	if *port == DEFAULT_FLAG_PORT && os.Getenv(ENVIRONMENT_VAR_PORT) != "" {
		flag.Set("port", os.Getenv(ENVIRONMENT_VAR_PORT))
	} else if *port == DEFAULT_FLAG_PORT && config[ENVIRONMENT_VAR_PORT] != "" {
		flag.Set("port", config[ENVIRONMENT_VAR_PORT])
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
	if *pushUsername == DEFAULT_FLAG_PUSH_USERNAME && os.Getenv(ENVIRONMENT_VAR_PUSH_USERNAME) != "" {
		flag.Set("push-username", os.Getenv(ENVIRONMENT_VAR_PUSH_USERNAME))
	} else if *pushUsername == DEFAULT_FLAG_PUSH_USERNAME && config[ENVIRONMENT_VAR_PUSH_USERNAME] != "" {
		flag.Set("push-username", config[ENVIRONMENT_VAR_PUSH_USERNAME])
	}
	if *pushPassword == DEFAULT_FLAG_PUSH_PASSWORD && os.Getenv(ENVIRONMENT_VAR_PUSH_PASSWORD) != "" {
		flag.Set("push-password", os.Getenv(ENVIRONMENT_VAR_PUSH_PASSWORD))
	} else if *pushPassword == DEFAULT_FLAG_PUSH_PASSWORD && config[ENVIRONMENT_VAR_PUSH_PASSWORD] != "" {
		flag.Set("push-password", config[ENVIRONMENT_VAR_PUSH_PASSWORD])
	}
	if *username != DEFAULT_FLAG_USERNAME && *password != DEFAULT_FLAG_PASSWORD &&
		*pushUsername == DEFAULT_FLAG_PUSH_USERNAME && *pushPassword == DEFAULT_FLAG_PUSH_PASSWORD {
		flag.Set("push-username", *username)
		flag.Set("push-password", *password)
	}

	//Get the Hostname of the machine
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var listner net.Listener
	listner, err = net.Listen("tcp", net.JoinHostPort(host, *port))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	_, *port, err = net.SplitHostPort(listner.Addr().String())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
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

	hh := heimdall.NewHeimdall(middleman, scopeFunc, pepFunc, failFunc)
	ch := advhttp.NewDefaultCorsHandler(hh)
	//ph := advhttp.NewPanicRecoveryHandler(ch)
	//lh := advhttp.NewLoggingHandler(ph, os.Stdout)
	lh := advhttp.NewLoggingHandler(ch, os.Stdout)
	hh.DB = memdb.NewMemDB()
	//hh.Templates = template.Must(template.ParseFiles())

	fmt.Fprintln(os.Stderr, "Share Server\tVersion "+VERSION)
	runtime.GOMAXPROCS(runtime.NumCPU())
	fmt.Fprintf(os.Stderr, "GOMAXPROCS=%v\n", runtime.NumCPU())
	serverProtocol := "http"
	if *certPath != DEFAULT_FLAG_CERT_PATH && *keyPath != DEFAULT_FLAG_KEY_PATH {
		serverProtocol = "https"
	}
	fmt.Fprintln(os.Stderr, "Serving "+serverProtocol+" on:")
	fmt.Fprintln(os.Stderr, "\thost\t"+net.JoinHostPort(hostname, *port))
	out, err := exec.Command("ip", "-4", "addr", "show").Output()
	if err == nil {
		re := regexp.MustCompile(`(?m)inet ([0-9].*)\/.*(\b.*[0-9])$`)
		vs := re.FindAllStringSubmatch(string(out), -1)
		for _, as := range vs {
			if len(as) == 3 {
				fmt.Fprintln(os.Stderr, "\t"+as[2]+"\t"+net.JoinHostPort(as[1], *port))
			}
		}
	}
	err = nil

	if *username != "" && *password != "" {
		//Put in the user(s) from config into the db
		user := hh.DB.NewUser()
		user.SetId(*username)
		user.SetName(*username)
		tu := user.(*memdb.User)
		tu.Username = *username
		tu.Password = *password
		hh.DB.CreateUser(user)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "User/Pass Required:")
		fmt.Fprintln(os.Stderr, "\tUsername: "+*username)
		fmt.Fprintln(os.Stderr, "\tPassword: "+*password)
		if *pushUsername != "" && *pushPassword != "" {
			pu := hh.DB.NewUser()
			pu.SetId(*pushUsername)
			pu.SetName(*pushUsername)
			tpu := pu.(*memdb.User)
			tpu.Username = *pushUsername
			tpu.Password = *pushPassword
			hh.DB.CreateUser(pu)
			fmt.Fprintln(os.Stderr, "Write User/Pass Required:")
			fmt.Fprintln(os.Stderr, "\tPush Username: "+*pushUsername)
			fmt.Fprintln(os.Stderr, "\tPush Password: "+*pushPassword)
		}
		fmt.Fprintln(os.Stderr, "\tcurl -u "+*username+":"+*password)
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Directories can be downloaded:")
	fmt.Fprintln(os.Stderr, "\t Visit /targz on any directory")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Files can be uploaded:")
	fmt.Fprintln(os.Stderr, "\tcurl --form \"file=@filename.txt\" "+serverProtocol+"://"+net.JoinHostPort(hostname, *port)+"/")
	fmt.Fprintln(os.Stderr, "\tcurl --data \"file=@filename.txt\" -H \"Content-Type: text/plain\" "+serverProtocol+"://"+net.JoinHostPort(hostname, *port)+"/")
	fmt.Fprintln(os.Stderr, "\tcurl -X PUT --data @filename.txt "+serverProtocol+"://"+net.JoinHostPort(hostname, *port)+"/filename.txt")
	fmt.Fprintln(os.Stderr, "\tVisit /upload.html on any directory")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "If the directory is a git repository (working or bare):")
	fmt.Fprintln(os.Stderr, "\tgit clone "+serverProtocol+"://"+net.JoinHostPort(hostname, *port))
	fmt.Fprintln(os.Stderr, "\tThere is also support for git push")
	fmt.Fprintln(os.Stderr, "\tgit push")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Press ctrl-c to stop sharing")

	if serverProtocol == "https" {
		certificate, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		config := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS10}
		tlsListener := tls.NewListener(listner, config)

		fmt.Fprintln(os.Stderr, http.Serve(tlsListener, lh))
		os.Exit(1)
	} else {
		fmt.Fprintln(os.Stderr, http.Serve(listner, lh))
		os.Exit(1)
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
	//Put in a header that says this was share that served the content
	w.Header().Set("Server", "Share/"+VERSION)
	w.Header().Set("X-Powered-By", runtime.Version())

	if r.Method == "DELETE" {
		if r.URL.Path == "/" {
			http.Error(w, "Can't delete main directory", http.StatusMethodNotAllowed)
			return
		}
		err := os.RemoveAll(filepath.Join(path, r.URL.Path))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}

	if r.Method == "GET" && strings.HasSuffix(r.URL.Path, ".md") && strings.Contains(r.Header.Get("Accept"), "text/html") {
		b, err := ioutil.ReadFile(filepath.Join(path, r.URL.Path))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		//Set up options
		e := blackfriday.CommonExtensions
		e = e | blackfriday.Footnotes
		e = e | blackfriday.DefinitionLists
		r := blackfriday.Run(b, blackfriday.WithExtensions(e))
		w.WriteHeader(http.StatusOK)
		w.Write(r)
		return
	}

	if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/targz") {
		if _, err := os.Stat(filepath.Join(path, r.URL.Path)); !os.IsNotExist(err) {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		filename := strings.Replace(filepath.Dir(r.URL.Path), "/", "-", -1)
		filename = filename[1:]
		if filename == "" {
			filename = "root"
		}
		filename += ".tar.gz"
		w.Header().Set("Content-Type", "application/x-tar")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")

		gw := gzip.NewWriter(w)
		defer gw.Close()

		tw := tar.NewWriter(gw)
		defer tw.Close()

		// tar bytes -> gzip bytes -> w bytes
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
				return err
			} else {
				h.Name = new_path
				if err = tw.WriteHeader(h); err != nil {
					return err
				}
			}
			if _, err := io.Copy(tw, fr); err != nil {
				return err
			}
			return nil
		})
		return
	}

	if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/upload.html") {
		fmt.Fprintf(w, `<html><title>Upload</title><body><form action="./" method="post" enctype="multipart/form-data"><label for="file">Filenames:</label><input id="file" type="file" name="file" multiple><input type="submit" name="submit" value="Submit"></form></body></html>`)
		return
	}

	//See if this is a git request
	if isGitRequest(r.URL.Path) {
		m.git.ServeHTTP(w, r)
		return
	}

	if r.Method == "POST" {
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Error(w, "POST is allowed on directories only", http.StatusNotFound)
			return
		}
		var successString string = ""
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && mt == "multipart/form-data" {
			os.MkdirAll(filepath.Dir(path)+r.URL.Path, 0775)
			reader, err := r.MultipartReader()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			for {
				part, err := reader.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				if part.FileName() != "" {
					os.MkdirAll(path[:len(path)-1]+r.URL.Path, 0775)
					file, err := os.Create(filepath.Dir(path) + r.URL.Path + part.FileName())
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					defer file.Close()

					size, err := io.Copy(file, part)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					w.Header().Add("Location", r.URL.Path+part.FileName())
					successString += fmt.Sprintf("Created: %v, Size: %v bytes\n", part.FileName(), size)
				}
				part.Close()
			}
		} else {
			if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && mt != "" {
				os.MkdirAll(filepath.Dir(path)+r.URL.Path, 0775)
				extension := extn.GetExtensionForMime(mt)
				if extension == "" {
					http.Error(w, "Content-Type not Understood", http.StatusUnsupportedMediaType)
					return
				}
				filename := GenUUIDv4() + extension
				file, err := os.Create(filepath.Dir(path) + r.URL.Path + filename)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				defer file.Close()

				size, err := io.Copy(file, r.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Location", r.URL.Path+filename)
				successString = fmt.Sprintf("Created: %v, Size: %v bytes\n", filename, size)
			} else {
				http.Error(w, "Need a valid Content-Type header", http.StatusUnsupportedMediaType)
				return
			}
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(successString))
		return
	}

	if r.Method == "PUT" {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.Error(w, "PUT is allowed on files only", http.StatusNotFound)
			return
		}
		//Need to strip the file off the path
		os.MkdirAll(filepath.Dir(path)+filepath.Dir(r.URL.Path), 0775)

		file, err := os.Create(filepath.Dir(path) + r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = io.Copy(file, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		return
	}

	m.file.ServeHTTP(w, r)
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

// Reads a user file, typically .share-users
// [username]
// 	password=password
// 	admin=true
//func readUsers(path string) (ret map[string]string) {
//}

// Reads an acl file, typically .share-acl
// +/- node verb(s) users
//func readACL(path string) (ret

func scopeFunc(r *http.Request, s string, c heimdall.Client, u heimdall.User) (int, string) {
	return heimdall.Deny, "Scope not supported in share at this point"
}

func pepFunc(r *http.Request, t heimdall.Token, c heimdall.Client, u heimdall.User) (int, string) {
	//Deny any access to */.share*
	if strings.HasSuffix(r.URL.Path, "/.share") {
		return heimdall.Deny, "The share file can't be viewed or modified"
	}
	if *pushUsername != "" && *pushPassword != "" && *username != "" && *password != "" {
		//The push user has all privs, and the regular user has read only privs
		if u != nil && u.GetName() == *pushUsername {
			return heimdall.Permit, "Welcome admin"
		}
		if u != nil && r.Method == "GET" || r.Method == "HEAD" && u.GetName() == *username {
			return heimdall.Permit, "Welcome user"
		}
		return heimdall.Deny, "Access to this site requires auth"
	} else if *pushUsername != "" && *pushPassword != "" {
		//Open auth reads, however you need permission to write
		if r.Method == "GET" || r.Method == "HEAD" {
			return heimdall.Permit, "Open auth read"
		} else if u != nil && u.GetName() == *pushUsername {
			return heimdall.Permit, "Welcome admin"
		}
		return heimdall.Deny, "Writes require auth"
	} else if *username != "" && *password != "" {
		//The only user has all privs
		if u != nil && u.GetName() == *username {
			return heimdall.Permit, "Welcome admin"
		}
		return heimdall.Deny, "Access to this site requires auth"
	}
	return heimdall.Permit, "This is an open auth share"
}

func failFunc(w http.ResponseWriter, r *http.Request, status int, message string, t heimdall.Token, c heimdall.Client, u heimdall.User) {
	if u != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="share"`)
		http.Error(w, message, http.StatusUnauthorized)
		return
	}
	http.Error(w, message, http.StatusForbidden)
}
