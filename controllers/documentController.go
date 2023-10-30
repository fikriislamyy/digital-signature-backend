package controllers

import (
	"backend/initializers"
	"backend/models"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func SignDocument(c *gin.Context) {
	files, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to upload documents",
		})
		return
	}

	// Get the user object from the context
	userObj, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "User object not found",
		})
		return
	}

	// Check if the "file" key is present in the uploaded files
	if _, ok := files.File["file"]; !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Please select at least on file to upload",
		})
		return
	}

	// Type-assert the user object to the appropriate type
	user, ok := userObj.(models.User)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid user object type",
		})
		return
	}

	for _, file := range files.File["file"] {

		// Open the PDF file
		pdfFile, err := file.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to open PDF file",
			})
			return
		}
		defer pdfFile.Close()

		// Read the PDF content
		pdfContent, err := io.ReadAll(pdfFile)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to read PDF file",
			})
			return
		}

		// Retrieve the user's private key based on the UserID (you may need to modify this based on your implementation)
		privateKey, err := GetUserPrivateKey(user.Email)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to retrieve private key",
			})
			return
		}

		// Sign the PDF using the SignMessage function
		signature, err := SignMessage(pdfContent, privateKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to sign PDF",
			})
			return
		}

		err = c.SaveUploadedFile(file, "assets/documents/"+file.Filename)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to save uploaded file",
			})
			return
		}

		// Save the PDF to the database
		document := models.Document{
			UserID:    user.ID,
			Name:      file.Filename,
			FilePath:  "assets/documents/" + file.Filename, // Set the file path based on your implementation
			Signature: signature,
			Signed:    true,
		}
		result := initializers.DB.Create(&document)
		if result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Failed to create document",
				"error":   result.Error.Error(),
			})
			return
		}

	}

	c.JSON(http.StatusOK, gin.H{
		"message": "PDF signed and stored successfully",
	})
}

func DownloadDocument(c *gin.Context) {
	documentID := c.Param("id")

	var document models.Document
	result := initializers.DB.First(&document, "id = ?", documentID)
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to retrieve document",
		})
		return
	}

	// Open the PDF file
	pdfFile, err := os.Open(document.FilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to open PDF file",
		})
		return
	}
	defer pdfFile.Close()

	// Read the PDF content
	pdfContent, err := io.ReadAll(pdfFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to read PDF file",
		})
		return
	}

	// Retrieve the uploaded public key file
	publicKeyFile, err := c.FormFile("publicKey")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to retrieve public key",
		})
		return
	}

	// Save the public key file to a temporary location
	publicKeyPath := "./temp/" + publicKeyFile.Filename
	err = c.SaveUploadedFile(publicKeyFile, publicKeyPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to save public key",
		})
		return
	}
	defer os.Remove(publicKeyPath)

	// Read the public key content
	publicKeyContent, err := os.ReadFile(publicKeyPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to read public key",
		})
		return
	}

	// Parse the public key content
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyContent)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to parse public key",
		})
		return
	}

	// Verify the signature
	err = VerifySignature(pdfContent, document.Signature, publicKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Signature verification failed",
		})
		return
	}

	// Set appropriate headers for file download
	c.Header("Content-Type", "application/pdf")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", document.Name))

	// Return the signed PDF file as the response
	c.File(document.FilePath)
}

func GetUserPrivateKey(email string) (*rsa.PrivateKey, error) {
	// Retrieve the user from the database based on the email
	var user models.User
	initializers.DB.First(&user, "email = ?", email)

	// Read the private key from the PEM file
	privateKeyBytes, err := os.ReadFile(user.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Parse the private key from the PEM bytes
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}

func SignMessage(message []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func VerifySignature(message, signature []byte, publicKey *rsa.PublicKey) error {
	hashedMessage := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashedMessage[:], signature)
	if err != nil {
		return fmt.Errorf("error verifying signature: %w", err)
	}
	return nil
}
