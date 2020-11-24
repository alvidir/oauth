package credential

import "time"

// Credential is a public key
type Credential struct {
	ID        string    `json:"id" bson:"_id,omitempty"`
	Name      string    `json:"name" bson:"name"`
	Public    string    `json:"public" bson:"public"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	Deadline  time.Time `json:"deadline,omitempty" bson:"deadline,omitempty"`
}

// GetID returns the name of a credential
func (cred *Credential) GetID() string {
	return cred.ID
}

// GetName returns the name of a credential
func (cred *Credential) GetName() string {
	return cred.Name
}

// GetPublic returns the public key of a credential
func (cred *Credential) GetPublic() string {
	return cred.Public
}
