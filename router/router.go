package router

import (
	"github.com/gin-gonic/gin"

	"wallet/controller"
)

func GetRouter() *gin.Engine {
	router := gin.Default()
	router.POST("/mnemonics", controller.NewMnemonic)
	router.POST("/wallets", controller.NewWallet)
	router.POST("/wallets/keystores", controller.NewWalletWithKeystore)
	return router
}
