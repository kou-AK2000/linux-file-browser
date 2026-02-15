package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

/* =========================================================
   ファイル情報構造体
   ========================================================= */

type FileInfo struct {
	Name string `json:"name"`

	Mode    string `json:"mode"`
	Perm    string `json:"perm"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`

	Uid uint32 `json:"uid"`
	Gid uint32 `json:"gid"`

	Owner string `json:"owner"`
	Group string `json:"group"`

	Nlink uint64 `json:"nlink"`
	IsDir bool   `json:"is_dir"`
}

/* ==========================================================
   設定構造体
   ========================================================== */

type Config struct {
	BaseDir string `json:"base_dir"` // 互換用（未使用でもOK）
	Allow   struct {
		Bin    bool `json:"bin"`
		Sbin   bool `json:"sbin"`
		Usr    bool `json:"usr"`
		Etc    bool `json:"etc"`
		VarLog bool `json:"var_log"`
	} `json:"allow"`
}

/* ========================================================= */

type SystemInfo struct {
	Hostname     string `json:"hostname"`
	Distribution string `json:"distribution"`
	Kernel       string `json:"kernel"`
	Arch         string `json:"arch"`
}

/* =========================================================
   グローバル
   ========================================================= */

var config Config

/* =========================================================
   パス解決
   ========================================================= */

func resolvePath(path string) string {
	return filepath.Clean(path)
}

/* =========================================================
   遷移許可判定（ホワイトリスト）
   ========================================================= */

func isAllowedPath(p string) bool {

	// 常に許可
	if p == "/" {
		return true
	}

	// /home は常に許可
	if p == "/home" || strings.HasPrefix(p, "/home/") {
		return true
	}

	// /bin
	if config.Allow.Bin &&
		(p == "/bin" || strings.HasPrefix(p, "/bin/")) {
		return true
	}

	// /sbin
	if config.Allow.Sbin &&
		(p == "/sbin" || strings.HasPrefix(p, "/sbin/")) {
		return true
	}

	// /usr
	if config.Allow.Usr &&
		(p == "/usr" || strings.HasPrefix(p, "/usr/")) {
		return true
	}

	// /etc
	if config.Allow.Etc &&
		(p == "/etc" || strings.HasPrefix(p, "/etc/")) {
		return true
	}

	// /var/log のみ許可（/var は不可）
	if config.Allow.VarLog &&
		(p == "/var/log" || strings.HasPrefix(p, "/var/log/")) {
		return true
	}

	return false
}

/* =========================================================
   ファイル一覧API
   ========================================================= */

func handler(w http.ResponseWriter, r *http.Request) {

	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}

	cleanPath := filepath.Clean(path)

	resolved, err := filepath.EvalSymlinks(cleanPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// ★ resolvedでチェックする
	if !isAllowedPath(resolved) {
		http.NotFound(w, r)
		return
	}

	entries, err := os.ReadDir(resolved)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	var result []FileInfo

	for _, entry := range entries {

		info, err := entry.Info()
		if err != nil {
			continue
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		permStr := fmt.Sprintf("%o", info.Mode().Perm())

		uidStr := fmt.Sprint(stat.Uid)
		userName := uidStr
		if u, err := user.LookupId(uidStr); err == nil {
			userName = u.Username
		}

		gidStr := fmt.Sprint(stat.Gid)
		groupName := gidStr
		if g, err := user.LookupGroupId(gidStr); err == nil {
			groupName = g.Name
		}

		result = append(result, FileInfo{
			Name:    entry.Name(),
			Mode:    info.Mode().String(),
			Perm:    permStr,
			Size:    info.Size(),
			ModTime: info.ModTime().Format("2006-01-02 15:04"),
			Uid:     stat.Uid,
			Gid:     stat.Gid,
			Owner:   userName,
			Group:   groupName,
			Nlink:   uint64(stat.Nlink),
			IsDir:   entry.IsDir(),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

/* =========================================================
	ファイル閲覧API
   ========================================================= */

func fileViewHandler(w http.ResponseWriter, r *http.Request) {

	path := r.URL.Query().Get("path")
	if path == "" {
		http.NotFound(w, r)
		return
	}

	cleanPath := filepath.Clean(path)

	resolved, err := filepath.EvalSymlinks(cleanPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// ★ resolvedでチェック
	if !isAllowedPath(resolved) {
		http.NotFound(w, r)
		return
	}

	info, err := os.Stat(resolved)
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}

	// 2MB制限
	if info.Size() > 2*1024*1024 {
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	data, err := os.ReadFile(resolved)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if !isTextFile(data) {
		http.Error(w, "Binary file not supported", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
}

/* =========================================================
	テキスト判定関数
   ========================================================= */

func isTextFile(data []byte) bool {
	for _, b := range data {
		if b == 0 {
			return false
		}
	}
	return true
}

/* =========================================================
   設定読み込み
   ========================================================= */

func loadConfig() error {

	file, err := os.Open("config.json")
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewDecoder(file).Decode(&config)
}

/* =========================================================
   設定API
   ========================================================= */

func configGetHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func configUpdateHandler(w http.ResponseWriter, r *http.Request) {

	var newConfig Config

	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	config = newConfig

	file, err := os.Create("config.json")
	if err == nil {
		json.NewEncoder(file).Encode(config)
		file.Close()
	}

	w.WriteHeader(http.StatusOK)
}

/* =========================================================
   システム情報API
   ========================================================= */

func systemHandler(w http.ResponseWriter, r *http.Request) {

	hostname, _ := os.Hostname()

	info := SystemInfo{
		Hostname:     hostname,
		Distribution: getDistribution(),
		Kernel:       getKernelVersion(),
		Arch:         runtime.GOARCH,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func getDistribution() string {

	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			value := strings.TrimPrefix(line, "PRETTY_NAME=")
			return strings.Trim(value, `"`)
		}
	}
	return "unknown"
}

func getKernelVersion() string {

	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return "unknown"
	}

	var release []byte
	for _, c := range uname.Release {
		if c == 0 {
			break
		}
		release = append(release, byte(c))
	}

	return string(release)
}

/* =========================================================
   main
   ========================================================= */

func main() {

	if os.Geteuid() == 0 {
		fmt.Println("Do not run as root")
		os.Exit(1)
	}

	if err := loadConfig(); err != nil {
		fmt.Println("Failed to load config:", err)
		os.Exit(1)
	}

	http.HandleFunc("/api/list", handler)
	http.HandleFunc("/api/file", fileViewHandler)
	http.HandleFunc("/api/system", systemHandler)
	http.HandleFunc("/api/config", configGetHandler)
	http.HandleFunc("/api/config/update", configUpdateHandler)
	http.Handle("/", http.FileServer(http.Dir("./static")))

	fmt.Println("Server started at http://127.0.0.1:8080")
	http.ListenAndServe("127.0.0.1:8080", nil)
}
