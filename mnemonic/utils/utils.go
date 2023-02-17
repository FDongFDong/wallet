package utils

import (
	"github.com/gin-gonic/gin"
)

func ErrorHandler(err error, c *gin.Context, statusCode int) {
	if err != nil {
		c.JSON(statusCode, gin.H{"error": err.Error()})
		return
	}
}
