package configfile

// The file format. It is kept apart from the domain types so that the domain
// carries no serialisation tags and the file can evolve behind a version.

type fileDTO struct {
	Version int       `yaml:"version"`
	Mode    string    `yaml:"mode"`
	Uplinks []string  `yaml:"uplinks"`
	Geo     geoDTO    `yaml:"geo"`
	DNS     dnsDTO    `yaml:"dns"`
	Exits   []exitDTO `yaml:"exits"`
	Lists   []listDTO `yaml:"lists"`
	Policy  []ruleDTO `yaml:"policy"`
	Exempt  []string  `yaml:"exempt"`
	Guard   guardDTO  `yaml:"guard"`
	P2P     p2pDTO    `yaml:"p2p"`
}

type p2pDTO struct {
	Mode       string   `yaml:"mode"`
	Signatures []string `yaml:"signatures"`
	NDPI       *ndpiDTO `yaml:"ndpi"`
	Ban        banDTO   `yaml:"ban"`
}

type ndpiDTO struct {
	Enabled *bool  `yaml:"enabled"`
	Socket  string `yaml:"socket"`
	PeerTTL string `yaml:"peer_ttl"`
}

type banDTO struct {
	Threshold int    `yaml:"threshold"`
	Window    string `yaml:"window"`
	TTL       string `yaml:"ttl"`
	Scope     string `yaml:"scope"`
}

type guardDTO struct {
	Mode  string         `yaml:"mode"`
	Rules []guardRuleDTO `yaml:"rules"`
}

type guardRuleDTO struct {
	Lists  []string `yaml:"lists"`
	Action string   `yaml:"action"`
	Log    bool     `yaml:"log"`
}

type dnsDTO struct {
	Port      uint16   `yaml:"port"`
	Upstreams []string `yaml:"upstreams"`
}

type geoDTO struct {
	GeoIP   string `yaml:"geoip"`
	GeoSite string `yaml:"geosite"`
}

type exitDTO struct {
	Name      string    `yaml:"name"`
	Slot      int       `yaml:"slot"`
	Iface     string    `yaml:"iface"`
	Conf      string    `yaml:"conf"`
	Endpoints []string  `yaml:"endpoints"`
	Health    healthDTO `yaml:"health"`
	Renew     *renewDTO `yaml:"renew"`
}

type renewDTO struct {
	Command []string `yaml:"command"`
	After   string   `yaml:"after"`
	Every   string   `yaml:"every"`
}

type healthDTO struct {
	URL    string `yaml:"url"`
	Expect string `yaml:"expect"`
}

type listDTO struct {
	Name      string     `yaml:"name"`
	IP        []string   `yaml:"ip"`
	ExtraCIDR []string   `yaml:"extra_cidr"`
	Domain    []string   `yaml:"domain"`
	Suffix    []string   `yaml:"suffix"`
	Bounds    *boundsDTO `yaml:"bounds"`
	Checksum  string     `yaml:"checksum"`
	Refresh   string     `yaml:"refresh"`
}

// boundsDTO has pointer fields: a bound left out takes its default, a bound
// written as zero is the file's — and invalid.
type boundsDTO struct {
	Min       *int     `yaml:"min"`
	Max       *int     `yaml:"max"`
	MaxChange *float64 `yaml:"max_change"`
}

type ruleDTO struct {
	Lists    []string `yaml:"lists"`
	Action   string   `yaml:"action"`
	Fallback string   `yaml:"fallback"`
}
