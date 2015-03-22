package extn

import (
	"bufio"
	"os"
	"strings"
)

var typeFiles = []string{
	"/etc/mime.types",
	"/etc/apache2/mime.types",
	"/etc/apache/mime.types",
}

func initMime() {
	for _, filename := range typeFiles {
		loadMimeFile(filename)
	}
}

func loadMimeFile(filename string) {
	f, err := os.Open(filename)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) <= 1 || fields[0][0] == '#' {
			continue
		}
		mimeType := fields[0]
		for _, ext := range fields[1:] {
			if ext[0] == '#' {
				break
			}
			extnmap[mimeType] = "." + ext
		}
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
}
