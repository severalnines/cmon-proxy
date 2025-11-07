package user

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthContext struct {
	Request *http.Request
	Context *gin.Context // Optional: gin context for accessing router
}
