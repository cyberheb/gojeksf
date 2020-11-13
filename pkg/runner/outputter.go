package runner

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cyberheb/gojeksf/pkg/resolve"
	"github.com/gocolly/colly/v2"
	jsoniter "github.com/json-iterator/go"
)

// OutPutter outputs content to writers.
type OutPutter struct {
	JSON bool
}

type jsonResult struct {
	Host   string `json:"host"`
	IP     string `json:"ip"`
	Source string `json:"source"`
}

type jsonSourceResult struct {
	Date    string   `json:"date"`
	Host    string   `json:"host"`
	Sources []string `json:"sources"`
	Path    []string `json:"path"`
}

// NewOutputter creates a new Outputter
func NewOutputter(json bool) *OutPutter {
	return &OutPutter{JSON: json}
}

func (o *OutPutter) createFile(filename string, appendtoFile bool) (*os.File, error) {
	if filename == "" {
		return nil, errors.New("empty filename")
	}

	dir := filepath.Dir(filename)

	if dir != "" {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			err := os.MkdirAll(dir, os.ModePerm)
			if err != nil {
				return nil, err
			}
		}
	}

	var file *os.File
	var err error
	if appendtoFile {
		file, err = os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	} else {
		file, err = os.Create(filename)
	}
	if err != nil {
		return nil, err
	}

	return file, nil
}

// WriteForChaos prepares the buffer to upload to Chaos
func (o *OutPutter) WriteForChaos(results map[string]resolve.HostEntry, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}

	for _, result := range results {
		sb.WriteString(result.Host)
		sb.WriteString("\n")

		_, err := bufwriter.WriteString(sb.String())
		if err != nil {
			bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}

// WriteHostIP writes the output list of subdomain to an io.Writer
func (o *OutPutter) WriteHostIP(results map[string]resolve.Result, writer io.Writer) error {
	var err error
	if o.JSON {
		err = writeJSONHostIP(results, writer)
	} else {
		err = writePlainHostIP(results, writer)
	}
	return err
}

func writePlainHostIP(results map[string]resolve.Result, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}

	for _, result := range results {
		sb.WriteString(result.Host)
		sb.WriteString(",")
		sb.WriteString(result.IP)
		sb.WriteString(",")
		sb.WriteString(result.Source)
		sb.WriteString("\n")

		_, err := bufwriter.WriteString(sb.String())
		if err != nil {
			bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}

func writeJSONHostIP(results map[string]resolve.Result, writer io.Writer) error {
	encoder := jsoniter.NewEncoder(writer)

	var data jsonResult

	for _, result := range results {
		data.Host = result.Host
		data.IP = result.IP
		data.Source = result.Source

		err := encoder.Encode(&data)
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteHostNoWildcard writes the output list of subdomain with nW flag to an io.Writer
func (o *OutPutter) WriteHostNoWildcard(results map[string]resolve.Result, writer io.Writer) error {
	hosts := make(map[string]resolve.HostEntry)
	for host, result := range results {
		hosts[host] = resolve.HostEntry{Host: result.Host, Source: result.Source}
	}

	return o.WriteHost(hosts, writer)
}

// WriteHost writes the output list of subdomain to an io.Writer
func (o *OutPutter) WriteHost(results map[string]resolve.HostEntry, writer io.Writer) error {
	var err error
	if o.JSON {
		err = writeJSONHost(results, writer)
	} else {
		err = writePlainHost(results, writer)
	}
	return err
}

func writePlainHost(results map[string]resolve.HostEntry, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}

	for _, result := range results {
		sb.WriteString(result.Host)
		sb.WriteString("\n")

		_, err := bufwriter.WriteString(sb.String())
		if err != nil {
			bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}

func writeJSONHost(results map[string]resolve.HostEntry, writer io.Writer) error {
	encoder := jsoniter.NewEncoder(writer)

	for _, result := range results {
		err := encoder.Encode(result)
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteHostIP writes the output list of subdomain to an io.Writer
func (o *OutPutter) WriteSourceHost(sourceMap map[string]map[string]struct{}, writer io.Writer) error {
	var err error
	if o.JSON {
		err = writeSourceJSONHost(sourceMap, writer)
	} else {
		err = writeSourcePlainHost(sourceMap, writer)
	}
	return err
}

func scrape(host string) []string {

	urlPath := make([]string, 0, 100)

	parsedHost, _ := url.Parse(host)

	// Instantiate default collector
	c := colly.NewCollector(
		colly.AllowedDomains(parsedHost.Host),
		colly.MaxDepth(2),
	)

	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: 10,
	})

	// On every a element which has href attribute call callback
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		parsedUrl, err := url.Parse(link)
		if err != nil {
			log.Fatal(err)
		}
		if !strings.HasPrefix(parsedUrl.Scheme, "javascript") || strings.HasPrefix(parsedUrl.Scheme, "http") ||
			strings.HasPrefix(parsedUrl.Scheme, "https") {
			if strings.HasPrefix(parsedUrl.Path, "/") {
				urlPath = append(urlPath, parsedUrl.Path)
			}
		}
		// Visit link found on page
		// Only those links are visited which are in AllowedDomains
		c.Visit(e.Request.AbsoluteURL(link))
	})

	stop := false
	c.OnError(func(_ *colly.Response, _ error) {
		stop = true
	})

	// Before making a request print "Visiting ..."
	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Scrapping", r.URL.String())
	})

	// Start scraping on host
	c.Visit(host)

	return urlPath

}

func writeSourceJSONHost(sourceMap map[string]map[string]struct{}, writer io.Writer) error {
	encoder := jsoniter.NewEncoder(writer)
	encoder.SetIndent("", "")

	var data jsonSourceResult

	for host, sources := range sourceMap {
		// Write date
		now := time.Now()
		data.Date = now.Format("2006.01.02 15:04:05")

		data.Host = host
		url := "https://" + host
		scrapePath := scrape(url)

		data.Path = scrapePath

		keys := make([]string, 0, len(sources))
		for source := range sources {
			keys = append(keys, source)
		}
		data.Sources = keys

		err := encoder.Encode(&data)
		if err != nil {
			return err
		}
	}
	return nil
}

func writeSourcePlainHost(sourceMap map[string]map[string]struct{}, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}

	for host, sources := range sourceMap {
		sb.WriteString(host)
		sb.WriteString(",[")
		sourcesString := ""
		for source := range sources {
			sourcesString += source + ","
		}
		sb.WriteString(strings.Trim(sourcesString, ", "))
		sb.WriteString("]\n")

		_, err := bufwriter.WriteString(sb.String())
		if err != nil {
			bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}
