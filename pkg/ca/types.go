package ca

type CAType string

const (
	CATypeKubernetes  CAType = "kubernetes-ca"
	CATypeETCD        CAType = "etcd-ca"
	CATypeFrontProxy  CAType = "front-proxy-ca"
)

func (c CAType) String() string {
	return string(c)
}

func (c CAType) IsValid() bool {
	return c == CATypeKubernetes || c == CATypeETCD || c == CATypeFrontProxy
}

// AllCATypes returns all valid CA types
func AllCATypes() []CAType {
	return []CAType{
		CATypeKubernetes,
		CATypeETCD,
		CATypeFrontProxy,
	}
}