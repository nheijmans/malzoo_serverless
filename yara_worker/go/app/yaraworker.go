package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/hillu/go-yara/v4"
)

type MyEvent struct {
	Name string `json:"name"`
}

func main() {
	lambda.Start(handler)
}

func handler(ctx context.Context, event MyEvent) {
	var (
		rules   rules
		threads int
	)

	var args = make([]string, 1)
	args = append(args, "/function/putty.exe")
	myrule := rule{"", "/function/bayshore_file_type_detect.yara"}
	rules = append(rules, myrule)

	c, err := yara.NewCompiler()
	if err != nil {
		log.Fatalf("Failed to initialize YARA compiler: %s", err)
	}
	for _, rule := range rules {
		f, err := os.Open(rule.filename)
		if err != nil {
			log.Fatalf("Could not open rule file %s: %s", rule.filename, err)
		}
		err = c.AddFile(f, rule.namespace)
		f.Close()
		if err != nil {
			log.Fatalf("Could not parse rule file %s: %s", rule.filename, err)
		}
	}
	r, err := c.GetRules()
	if err != nil {
		log.Fatalf("Failed to compile rules: %s", err)
	}

	wg := sync.WaitGroup{}
	wg.Add(threads)

	ch := make(chan string, threads)
	for i := 0; i < threads; i++ {
		s, _ := yara.NewScanner(r)
		go func(ch chan string, tid int) {
			for filename := range ch {
				var m yara.MatchRules
				log.Printf("<%02d> Scanning file %s... ", tid, filename)
				err := s.SetCallback(&m).ScanFile(filename)
				printMatches(filename, m, err)
			}
			wg.Done()
		}(ch, i)
	}
	for _, path := range args {
		if err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if info.Mode().IsRegular() {
				ch <- path
			} else if info.Mode().IsDir() {
				return nil
			} else {
				log.Printf("Sipping %s", path)
			}
			return nil
		}); err != nil {
			log.Printf("walk: %s: %s", path, err)
		}
	}
	close(ch)

	return

}

func printMatches(item string, m []yara.MatchRule, err error) {
	if err != nil {
		log.Printf("%s: error: %s", item, err)
		return
	}
	if len(m) == 0 {
		log.Printf("%s: no matches", item)
		return
	}
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "%s: [", item)
	for i, match := range m {
		if i > 0 {
			fmt.Fprint(buf, ", ")
		}
		fmt.Fprintf(buf, "%s:%s", match.Namespace, match.Rule)
	}
	fmt.Fprint(buf, "]")
	log.Print(buf.String())

	return
}
