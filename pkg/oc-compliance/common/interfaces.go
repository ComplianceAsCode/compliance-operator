package common

import (
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubectl/pkg/scheme"
)

// ObjectHelper is a generic interface to implement actions
// that are to be executed on an object
type ObjectHelper interface {
	Handle() error
}

// KubeClientUser is an interface to use kubeclients on a specific namespace
type KubeClientUser interface {
	DynamicClient() dynamic.Interface
	Clientset() kubernetes.Interface
	GetConfig() *rest.Config
	GetNamespace() string
}

func NewKubeClientUser(cfgflags *genericclioptions.ConfigFlags, ns string) (KubeClientUser, error) {
	var err error
	kuser := &kubeClientUserImp{}
	kuser.cfg, err = cfgflags.ToRESTConfig()
	if err != nil {
		panic(err)
	}

	// NOTE(jaosorior): workaround for https://github.com/kubernetes/client-go/issues/657
	kuser.cfg.GroupVersion = &schema.GroupVersion{Group: "", Version: "v1"}
	kuser.cfg.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	// NOTE(jaosorior): This is needed so the appropriate api path is used.
	kuser.cfg.APIPath = "/api"

	kuser.clientset, err = kubernetes.NewForConfig(kuser.cfg)
	if err != nil {
		panic(err)
	}

	kuser.dynclient, err = dynamic.NewForConfig(kuser.cfg)
	if err != nil {
		panic(err)
	}

	rawConfig, err := cfgflags.ToRawKubeConfigLoader().RawConfig()
	if err != nil {
		return nil, err
	}

	// Takes precedence
	if ns != "" {
		kuser.namespace = ns
	} else if currentContext, exists := rawConfig.Contexts[rawConfig.CurrentContext]; exists {
		if currentContext.Namespace != "" {
			kuser.namespace = currentContext.Namespace
		}
	}

	return kuser, nil
}

type kubeClientUserImp struct {
	dynclient dynamic.Interface
	clientset kubernetes.Interface
	cfg       *rest.Config
	namespace string
}

func (kuser *kubeClientUserImp) DynamicClient() dynamic.Interface {
	return kuser.dynclient
}

func (kuser *kubeClientUserImp) Clientset() kubernetes.Interface {
	return kuser.clientset
}

func (kuser *kubeClientUserImp) GetConfig() *rest.Config {
	return kuser.cfg
}

func (kuser *kubeClientUserImp) GetNamespace() string {
	return kuser.namespace
}

type CommandContext struct {
	ConfigFlags *genericclioptions.ConfigFlags

	Kuser KubeClientUser

	Helper ObjectHelper

	Args []string

	genericclioptions.IOStreams
}

// Complete sets all information required for updating the current context
func (o *CommandContext) Complete(cmd *cobra.Command, args []string) error {
	o.Args = args

	// Takes precedence
	givenNamespace, err := cmd.Flags().GetString("namespace")
	if err != nil {
		return err
	}
	o.Kuser, err = NewKubeClientUser(o.ConfigFlags, givenNamespace)
	if err != nil {
		return err
	}
	return nil
}
