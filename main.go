package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "os/exec"
    "runtime"
)

type ips struct {
    Network    network   `json:"network"`
    Location   location  `json:"location"`
    Detections types     `json:"detections"`
}

type network struct {
    Hostname     string `json:"hostname"`
    Provider     string `json:"provider"`
    Organisation string `json:"organisation"`
    Type         string `json:"type"`
}

type location struct {
    CountryName string `json:"country_name"`
    RegionName  string `json:"region_name"`
    RegionCode  string `json:"region_code"`
    CityName    string `json:"city_name"`
}

type types struct {
    Proxy       bool `json:"proxy"`
    VPN         bool `json:"vpn"`
    Compromised bool `json:"compromised"`
    Scraper     bool `json:"scraper"`
    Hosting     bool `json:"hosting"`
    Anonymous   bool `json:"anonymous"`
}

func clearConsole() {
    var cmd *exec.Cmd
    if runtime.GOOS == "windows" {
        cmd = exec.Command("cmd", "/c", "cls")
    } else {
        cmd = exec.Command("clear")
    }
    cmd.Stdout = os.Stdout
    cmd.Run()
}

func main() {
    if len(os.Args) < 2 {
        fmt.Println("Usage: go run main.go <IP>")
        return
    }

    ip := os.Args[1]
    url := fmt.Sprintf("https://proxycheck.io/v3/%s", ip)
    link := fmt.Sprintf("https://proxycheck.io/ip/%s", ip)

    resp, err := http.Get(url)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        panic(err)
    }

    var raw map[string]json.RawMessage
    if err := json.Unmarshal(body, &raw); err != nil {
        panic(err)
    }

    clearConsole()

    cyan := "\033[1;36m"
    reset := "\033[0m"

    fmt.Printf("\n%sQueried IP:%s %s\n\n", cyan, reset, ip)


    for key, val := range raw {
        if key == "status" || key == "query_time" {
            continue
        }

        var info ips
        if err := json.Unmarshal(val, &info); err != nil {
            panic(err)
        }

        green := "\033[1;32m"

        fmt.Printf("%sNetwork Info%s\n", green, reset)
        fmt.Printf("  Hostname     : %s\n", info.Network.Hostname)
        fmt.Printf("  Provider     : %s\n", info.Network.Provider)
        fmt.Printf("  Organisation : %s\n", info.Network.Organisation)
        fmt.Printf("  Type         : %s\n\n", info.Network.Type)

        fmt.Printf("%sLocation Info%s\n", green, reset)
        fmt.Printf("  Country      : %s\n", info.Location.CountryName)
        fmt.Printf("  Region       : %s (%s)\n", info.Location.RegionName, info.Location.RegionCode)
        fmt.Printf("  City         : %s\n\n", info.Location.CityName)

        fmt.Printf("%sDetections%s\n", green, reset)
        fmt.Printf("  Proxy        : %v\n", info.Detections.Proxy)
        fmt.Printf("  VPN          : %v\n", info.Detections.VPN)
        fmt.Printf("  Compromised  : %v\n", info.Detections.Compromised)
        fmt.Printf("  Scraper      : %v\n", info.Detections.Scraper)
        fmt.Printf("  Hosting      : %v\n", info.Detections.Hosting)
        fmt.Printf("  Anonymous    : %v\n", info.Detections.Anonymous)
        
        fmt.Printf("\n%sView full results here:%s %s\n\n", cyan, reset, link)
    }
}