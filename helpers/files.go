package helpers

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"sync"
)

var wg sync.WaitGroup

func ReadFile(fileName, processName, parserName, filter string, concurrency int) {
	var sem = make(chan int, concurrency)

	content, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatal(err)
	}

	s := bufio.NewScanner(bytes.NewReader(content))

	for s.Scan() {
		sem <- 1
		wg.Add(1)
		text := s.Text()
		go func(text string) {
			w := bufio.NewWriter(os.Stdout)
			parser(w, text, processName, parserName, filter)
			<-sem
		}(text)
	}
	wg.Wait()

	if err := s.Err(); err != nil {
		log.Fatal(err)
	}

}