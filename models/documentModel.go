package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Document struct {
	gorm.Model
	UserID    uuid.UUID `gorm:"type:uuid;index" json:"user_id"`
	User      User      // Belongs to User model
	Name      string    // Name of the document
	FilePath  string    // File path to the document
	Signature []byte    // Signature of the document (generated using SignMessage)
	Signed    bool      // Indicates whether the document has been signed
}
