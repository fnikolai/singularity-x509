// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package engines

import (
	"encoding/json"
	"net"
	"net/rpc"

	"github.com/singularityware/singularity/src/pkg/sylog"
	"github.com/singularityware/singularity/src/runtime/engines/common/config"
	"github.com/singularityware/singularity/src/runtime/engines/singularity"
	singularityRpcServer "github.com/singularityware/singularity/src/runtime/engines/singularity/rpc/server"
)

// Engine is the combination of an EngineOperations and a config.Common. The singularity
// startup routines (src/runtime/startup/*) can spawn a container process from this type
type Engine struct {
	EngineOperations
	*config.Common
}

// EngineOperations is an interface describing necessary operations to launch a
// container process.
type EngineOperations interface {
	// Config returns the current EngineConfig, used to populate the Common struct
	Config() config.EngineConfig
	// InitConfig is responsible for storing the parse config.Common inside
	// the EngineOperations implementation.
	InitConfig(*config.Common)
	// CheckConfig is called in stage1 to validate the values of the configuration
	CheckConfig() error
	// IsRunAsInstance returns whether or not the container is an instance or batch
	IsRunAsInstance() bool
	// CreateContainer is called in stage2-child and does mount operations, etc... to
	// set up the container environment for the payload proc
	CreateContainer(rpcConn net.Conn) error
	// PrestartProcess is called in stage2-parent before waiting on stage2-child and can do
	// some set-up operations before the container proc is spawned
	PrestartProcess() error
	// StartProcess is called in stage2-parent after waiting on stage2-child exit. It is
	// responsible for exec'ing the payload proc in the container
	StartProcess() error
	// MonitorContainer is called in smaster once the container proc has been spawned. It
	// will typically block until the container proc exists
	MonitorContainer() error
	// CleanupContainer is called in smaster after the MontiorContainer returns. It is responsible
	// for ensuring that the container has been properly torn down
	CleanupContainer() error
}

// NewEngine returns the engine described by the JSON []byte configuration
func NewEngine(b []byte) (*Engine, error) {
	// Parse json []byte into map to first grab engineName value
	jsonMap := make(map[string]interface{})
	if err := json.Unmarshal(b, &jsonMap); err != nil {
		return nil, err
	}

	// Convert engineName from interface{} to string type
	engineName := jsonMap["engineName"].(string)

	// Ensure engineName exists
	if _, ok := registeredEngineOperations[engineName]; !ok {
		sylog.Fatalf("Engine named %s not found, failing\n", engineName)
	}

	// Create empty Engine object with properly initialized EngineConfig && EngineOperations
	e := &Engine{
		EngineOperations: registeredEngineOperations[engineName],
		Common: &config.Common{
			EngineConfig: registeredEngineOperations[engineName].Config(),
		},
	}

	// Use Unmarshal func on Engine type to convert JSON into filled Engine struct
	if err := json.Unmarshal(b, e); err != nil {
		return nil, err
	}
	return e, nil
}

// UnmarshalJSON is for json.Unmarshaler
func (e *Engine) UnmarshalJSON(b []byte) error {
	// Unmarshal into e.Common
	if err := json.Unmarshal(b, e.Common); err != nil {
		sylog.Errorf("Unable to parse JSON into e.Common: %s\n", err)
		return err
	}

	// Initialize the EngineOperations config pointers
	e.InitConfig(e.Common)
	return nil
}

var registeredEngineOperations map[string]EngineOperations

func registerEngineOperations(e EngineOperations, name string) {
	registeredEngineOperations[name] = e
}

// registerEngineRPCMethods contains a map relating an Engine name to a set
// of RPC methods served by RPC server
var registeredEngineRPCMethods map[string]interface{}

// registerEngineRPCMethods registers RPC server methods for runtime engine
func registerEngineRPCMethods(methods interface{}, name string) {
	registeredEngineRPCMethods[name] = methods
}

// ServeRuntimeEngineRequests serves runtime engine requests with corresponding
// registered engine methods
func ServeRuntimeEngineRequests(name string, conn net.Conn) {
	methods := registeredEngineRPCMethods[name]
	rpc.RegisterName(name, methods)
	rpc.ServeConn(conn)
}

func init() {
	registeredEngineOperations = make(map[string]EngineOperations)
	registeredEngineRPCMethods = make(map[string]interface{})

	methods := new(singularityRpcServer.Methods)
	registerEngineOperations(&singularity.EngineOperations{EngineConfig: singularity.NewConfig()}, "singularity")
	registerEngineRPCMethods(methods, singularity.Name)
}
