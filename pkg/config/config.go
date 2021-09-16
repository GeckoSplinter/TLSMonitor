package config

type Config struct {
	Metrics     Metrics  `yaml:"metrics"`
	NbDialRetry int      `yaml:"nbDialRetry"`
	Hosts       []string `yaml:"hosts,omitempty"`
	CertsPaths  []string `yaml:"certsPaths,omitempty"`
}

type Metrics struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
	Port    int    `yaml:"port"`
}
