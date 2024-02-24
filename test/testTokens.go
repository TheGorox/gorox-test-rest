package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type RefreshTokenBody struct {
	RefreshToken string `json:"refreshToken"`
}

func truncateString(str string, maxLength int) string {
	if len(str) <= maxLength {
		return str
	}

	truncated := str[:maxLength] + "..."
	return truncated
}

func main() {
	/*
		/get тест
	*/
	getTokenResponse, err := http.Get("http://localhost:3000/token/get?uuid=1234-5678-9012-3456")
	if err != nil {
		fmt.Println("/token/get error ", err)
		return
	}
	defer getTokenResponse.Body.Close()

	decoder := json.NewDecoder(getTokenResponse.Body)
	var refreshTokenDecoded RefreshTokenBody
	err = decoder.Decode(&refreshTokenDecoded)
	if err != nil {
		fmt.Println("/token/get parse body error ", err)
		return
	}

	refreshToken := refreshTokenDecoded.RefreshToken

	setCookie := getTokenResponse.Cookies()
	// представим что тесты всегда на локалхосте и
	// никакие google/яндекс статистики не испортят нам веселье
	if len(setCookie) != 1 {
		fmt.Println("/token/get Set-Cookie invalid length: ", setCookie)
		return
	}

	accessToken := setCookie[0].Value

	fmt.Printf("/token/get pass, refresh_token=%s, token=%s\n", truncateString(refreshToken, 30), truncateString(accessToken, 30))

	/*
		/refresh первый тест
	*/

	// p.s. 0L3QtdC90LDQstC40LbRgyBHbw==
	req, err := http.NewRequest("GET", "http://localhost:3000/token/refresh?refreshToken="+refreshToken, nil)
	if err != nil {
		fmt.Println("/token/refresh create request error ", err)
		return
	}

	req.AddCookie(setCookie[0])

	refreshResp, err := http.DefaultClient.Do(req)

	if err != nil {
		fmt.Println("/token/refresh error ", err)
		return
	}
	defer refreshResp.Body.Close()

	if refreshResp.StatusCode != 200 {
		fmt.Printf("/token/refresh bad status %d\n", refreshResp.StatusCode)
		return
	}

	decoder = json.NewDecoder(refreshResp.Body)
	var newRefreshTokenDecoded RefreshTokenBody
	err = decoder.Decode(&newRefreshTokenDecoded)
	if err != nil {
		fmt.Println("/token/refresh parse body error ", err)
		return
	}
	newRefreshToken := newRefreshTokenDecoded.RefreshToken

	newSetCookie := getTokenResponse.Cookies()
	if len(setCookie) != 1 {
		fmt.Println("/token/refresh Set-Cookie invalid length: ", setCookie)
		return
	}

	newAccessToken := newSetCookie[0].Value

	fmt.Printf("/token/refresh pass, new_refresh_token=%s, new_token=%s\n", truncateString(newRefreshToken, 30), truncateString(newAccessToken, 30))
	

	/*
		/refresh тест на повторное использование refresh токена
	*/

	req, err = http.NewRequest("GET", "http://localhost:3000/token/refresh?refreshToken="+refreshToken, nil)
	if err != nil {
		fmt.Println("/token/refresh test2 create request error ", err)
		return
	}

	req.AddCookie(setCookie[0])

	refreshResp, err = http.DefaultClient.Do(req)

	if err != nil {
		fmt.Println("/token/refresh test2 error ", err)
		return
	}
	defer refreshResp.Body.Close()

	if refreshResp.StatusCode != 400 {
		fmt.Println("/token/refresh test2 status mismatch: ", refreshResp.StatusCode)
		return
	}

	fmt.Println("/token/refresh test2 pass (/refresh with old refreshToken is blocked)")


	fmt.Println("all tests passed!!")
	// ура
}