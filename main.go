package main

import (
	"bufio"
	"github.com/beevik/etree"
	"os"
	"strings"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func parseContentFilerRules(ESAconfigFile string, contentFilterName string, parsedFileName string) {
	ESAconfig := etree.NewDocument()
	if err := ESAconfig.ReadFromFile(ESAconfigFile); err != nil {
		panic(err)
	}
	root := ESAconfig.SelectElement("cluster_config")
	for _, contentFilter := range ESAconfig.FindElements(root.Tag + "/cluster/config/perrcpt_policies/inbound_policies/content_filters/*") {
		if contentFilter.SelectElement("filter_name").Text() == contentFilterName {
			f, err := os.Create(parsedFileName)
			check(err)
			for _, rule := range contentFilter.SelectElements("rule") {
				for _, ruleData := range rule.SelectElements("rule_data") {
					parsedRule := strings.Replace(ruleData.Text(), "^", "", -1)
					parsedRule = strings.Replace(parsedRule, "@", "", -1)
					parsedRule = strings.Replace(parsedRule, "$", "", -1)
					w := bufio.NewWriter(f)
					_, err = w.WriteString(parsedRule + "\n")
					check(err)
					w.Flush()
				}
			}
		}

	}
}

func main() {
	parseContentFilerRules("config_utf-8.xml", "Reject_ip", "Reject_ip.txt")
}
