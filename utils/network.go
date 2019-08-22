package utils

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

// GetIPFromRequest gets ip from current request
func GetIPFromRequest(req *http.Request) (net.IP, error) {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("userip: %q is not IP:port", req.RemoteAddr)
	}

	userIP := net.ParseIP(ip)
	if userIP == nil {
		return nil, fmt.Errorf("userip: %q is not IP:port", req.RemoteAddr)
	}
	return userIP, nil
}

// LogRequest log user request
func LogRequest(req *http.Request, route string) {
	ip, err := GetIPFromRequest(req)
	if err != nil {
		log.Println("[ERROR] Cannot get user ip!", err)
		// http.Error(w, "Cannot get user ip!", 400)
		// return
	}

	logStr := fmt.Sprintf("IP: %v, Route: %s", ip, route)

	log.Printf(logStr)
	go writeLogToFile(logStr)
}

func writeLogToFile(data string) {
	t := time.Now()
	date := fmt.Sprintf(t.Format("2006-01-02"))
	path := fmt.Sprintf("./logs/%s-log.log", date)

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("[ERROR] Cannot create file!", err)
	}
	defer file.Close()

	hour := strconv.Itoa(t.Hour())
	if len(hour) == 1 {
		hour = fmt.Sprintf("0%v", hour)
	}

	minutes := strconv.Itoa(t.Minute())
	if len(minutes) == 1 {
		minutes = fmt.Sprintf("0%v", minutes)
	}

	seconds := strconv.Itoa(t.Second())
	if len(seconds) == 1 {
		seconds = fmt.Sprintf("0%v", seconds)
	}

	file.WriteString(fmt.Sprintln(fmt.Sprintf("%v:%v:%v:%d | ", hour, minutes, seconds, t.Nanosecond()), data))
}
