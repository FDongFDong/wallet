package main

import "wallet/mnemonic/router"

func main() {
	router := router.GetRouter()
	router.Run(":8080")
}
