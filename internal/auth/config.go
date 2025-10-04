package auth

const (
	HttpMethodAny = "ANY"
)

type ParamSource string

const (
	ParamSourcePath          ParamSource = "path"
	ParamSourceQuery         ParamSource = "query"
	ParamSourceHeader        ParamSource = "header"
	ParamSourceClaim         ParamSource = "claim"
	ParamSourceBasicAuthUser ParamSource = "basicAuthUser"
)

type ParamConfig struct {
	Name     string      `json:"name" yaml:"name" binding:"required"` // param name (e.g. "x" or "X-Name")
	Source   ParamSource `json:"source" yaml:"source" binding:"required,oneof=path query header claim basicAuthUser"`
	Default  string      `json:"default,omitempty" yaml:"default,omitempty"`   // optional fallback if value is empty
	Function string      `json:"function,omitempty" yaml:"function,omitempty"` // function
	Expr     string      `json:"expr,omitempty" yaml:"expr,omitempty"`         // expression
}

func (p *ParamConfig) Key() string {
	if len(p.Expr) != 0 {
		return p.Expr
	}
	return p.Name
}

type RuleConfig struct {
	//TODO: make Format and ParamNames required when Cases is empty
	Format     string   `json:"format,omitempty" yaml:"format,omitempty"`         // "%s-%s" -> "default" "%s"
	ParamNames []string `json:"paramNames,omitempty" yaml:"paramNames,omitempty"` // ["id", "q"]
	// conditionals
	Cases []RuleCase `json:"cases,omitempty" yaml:"cases,omitempty"`
}

type RuleCase struct {
	When       string   `json:"when,omitempty" yaml:"when,omitempty"`
	Format     string   `json:"format" yaml:"format"`
	ParamNames []string `json:"paramNames,omitempty" yaml:"paramNames,omitempty" binding:"dive,required"`
}

type RouteConfig struct {
	Routes []Route `json:"routes" yaml:"routes" binding:"dive,required"`
}

type Route struct {
	HttpMethod    string        `json:"httpMethod" yaml:"httpMethod" binding:"required,oneof=GET HEAD POST PUT PATCH DELETE CONNECT OPTIONS TRACE ANY"`
	RelativePaths []string      `json:"relativePaths" yaml:"relativePaths"`                      // e.g. "/user/:id"
	Params        []ParamConfig `json:"params,omitempty" yaml:"params,omitempty" binding:"dive"` // params to extract
	Rules         []RuleConfig  `json:"rules,omitempty" yaml:"rules,omitempty" binding:"dive"`   // cabin arguments (if missing -> use params)
}
