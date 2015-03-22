package extn

var extnmap map[string]string = make(map[string]string)

func init() {
	initMime()

	extnmap["text/plain"] = ".txt"
	extnmap["text/css"] = ".css"
	extnmap["text/html"] = ".html"
	extnmap["text/xml"] = ".xml"
	extnmap["image/gif"] = ".gif"
	extnmap["image/jpeg"] = ".jpg"
	extnmap["image/png"] = ".png"
	extnmap["application/json"] = ".json"
	extnmap["application/x-javascript"] = ".js"
	extnmap["application/pdf"] = ".pdf"
}

func GetExtensionForMime(mimeType string) string {
	return extnmap[mimeType]
}
