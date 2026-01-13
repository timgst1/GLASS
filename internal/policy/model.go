package policy

type Document struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`

	Subjects []Subject `yaml:"subjects"`
	Roles    []Role    `yaml:"roles"`
	Bindings []Binding `yaml:"bindings"`
}

type Subject struct {
	Name  string `yaml:"name"`
	Match struct {
		Kind string `yaml:"kind"`
		Name string `yaml:"name"`
	} `yaml:"match"`
}

type Role struct {
	Name        string       `yaml:"name"`
	Permissions []Permission `yaml:"permissions"`
}

type Permission struct {
	Action    string `yaml:"action"`
	KeyPrefix string `yaml:"keyPrefix"`
	KeyExact  string `yaml:"keyExact"`
}

type Binding struct {
	Subject string   `yaml:"subject"`
	Roles   []string `yaml:"roles"`
}
