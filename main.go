package main

import "wallet/router"

func main() {
	router := router.GetRouter()
	router.Run(":8080")
}
