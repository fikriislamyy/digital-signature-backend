package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	ID             uuid.UUID `gorm:"type:uuid;default:gen_random_uuid()"`
	Fullname       string
	Email          string `gorm:"unique"`
	Password       string
	PrivateKeyPath string
	PublicKeyPath  string
	Documents      []Document // One-to-Many relationship with Document model
}
