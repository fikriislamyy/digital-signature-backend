package controllers

import (
	"backend/initializers"
	"backend/models"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func GenerateKeyPair(bitSize int) (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, fmt.Errorf("error generating key pair: %w", err)
	}
	publicKey := &privateKey.PublicKey

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

func (kp *KeyPair) SavePrivatePEM(filename string) error {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(kp.PrivateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	err := os.WriteFile(filename, privateKeyPEM, 0600)
	if err != nil {
		return fmt.Errorf("error saving private key: %w", err)
	}
	return nil
}

func (kp *KeyPair) SavePublicPEM(filename string) error {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		return fmt.Errorf("error marshaling public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	err = os.WriteFile(filename, publicKeyPEM, 0644)
	if err != nil {
		return fmt.Errorf("error saving public key: %w", err)
	}
	return nil
}
func SignUp(c *gin.Context) {
	var body struct {
		Fullname string
		Email    string
		Password string
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})
		return
	}

	keyPair, err := GenerateKeyPair(2048)
	if err != nil {
		log.Fatalf("Error generating key pair: %v", err)
	}

	// Save private key as PEM
	err = keyPair.SavePrivatePEM("assets/keys/" + body.Email + "_private_key.pem")
	if err != nil {
		log.Fatalf("Error saving private key: %v", err)
	}

	// Save public key as PEM
	err = keyPair.SavePublicPEM("assets/keys/" + body.Email + "_public_key.pem")
	if err != nil {
		log.Fatalf("Error saving public key: %v", err)
	}

	user := models.User{
		Fullname:       body.Fullname,
		Email:          body.Email,
		Password:       string(hash),
		PrivateKeyPath: "assets/keys/" + body.Email + "_private_key.pem",
		PublicKeyPath:  "assets/keys/" + body.Email + "_public_key.pem",
	}

	result := initializers.DB.Create(&user)
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Email already exists",
			"title":   "Error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User created successfully",
		"title":   "Success",
	})
}

func Login(c *gin.Context) {
	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	var user models.User
	initializers.DB.First(&user, "email = ?", body.Email)

	if user.ID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid email or password",
			"title":   "Error",
		})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid email or password",
			"title":   "Error",
		})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 2).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to generate token",
		})
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"token":   tokenString,
		"message": "Login Successful",
		"title":   "Success",
	})
}

func Validate(c *gin.Context) {
	user, _ := c.Get("user")
	if userObj, ok := user.(models.User); ok {
		data := struct {
			ID       uuid.UUID `json:"id"`
			Fullname string    `json:"fullname"`
			Email    string    `json:"email"`
		}{
			ID:       userObj.ID,
			Fullname: userObj.Fullname,
			Email:    userObj.Email,
		}

		c.JSON(http.StatusOK, gin.H{
			"message": data,
		})
	}
}
