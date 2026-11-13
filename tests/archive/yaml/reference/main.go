// Independent YAML decoder version used by the fixed mihomo config baseline.
package main

import (
	"encoding/json"
	"go.yaml.in/yaml/v3"
	"io"
	"os"
)

type Raw struct {
	Port    int              `yaml:"port" json:"port"`
	Socks   int              `yaml:"socks-port" json:"socks-port"`
	Mixed   int              `yaml:"mixed-port" json:"mixed-port"`
	Allow   bool             `yaml:"allow-lan" json:"allow-lan"`
	Mode    string           `yaml:"mode" json:"mode"`
	Proxies []map[string]any `yaml:"proxies" json:"proxies"`
}

func main() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}
	raw := Raw{Mode: "rule"}
	err = yaml.Unmarshal(data, &raw)
	result := map[string]any{"ok": err == nil}
	if err == nil {
		result["value"] = raw
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
