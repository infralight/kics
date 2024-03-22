package converter

import (
	"encoding/json"

	"github.com/Checkmarx/kics/pkg/model"
)

// map[string]interface{}
/*
InLineDescriptions    string `json:"singleDescriptions"`
MultiLineDescriptions string `json:"multiDescriptions"`
linesToIgnore    []int                       `json:"-"`
linesNotToIgnore []int                       `json:"-"`
*/

const stringSecure = "secure"

type JSONBicep struct {
	Func      map[string]interface{}      `json:"func,omitempty"`
	Type      map[string]Type             `json:"definitions,omitempty"`
	Params    map[string]Param            `json:"-"`
	Variables []Variable                  `json:"variables,omitempty"`
	Resources []Resource                  `json:"resources,omitempty"`
	Outputs   []Output                    `json:"-"`
	Modules   []Module                    `json:"modules,omitempty"`
	Metadata  map[string]string           `json:"metadata,omitempty"`
	Lines     map[string]model.LineObject `json:"_kics_lines"`
}

type ElemBicep struct {
	Type     string
	Param    Param
	Metadata Metadata
	Variable Variable
	Resource Resource
	Output   Output
	Module   Module
}

type Decorator struct {
	Allowed   map[string]interface{} `json:"allowedValues,omitempty"`
	MaxLength string                 `json:"maxLength,omitempty"`
	MinLength string                 `json:"minLength,omitempty"`
	MaxValue  string                 `json:"maxValue,omitempty"`
	MinValue  string                 `json:"minValue,omitempty"`
	Metadata  []*Property            `json:"metadata,omitempty"`
}

type Metadata struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

type Param struct {
	Name         string                 `json:"-"`
	Type         string                 `json:"type"`
	DefaultValue interface{}            `json:"defaultValue,omitempty"`
	Metadata     *Metadata              `json:"metadata,omitempty"`
	Decorators   map[string]interface{} `json:"decorators,omitempty"`
}

type Variable struct {
	Name    string                 `json:"-"`
	IsArray bool                   `json:"-"`
	Value   interface{}            `json:"value,omitempty"`
	Prop    map[string]interface{} `json:"prop"`
}

type Resource struct {
	APIVersion string                 `json:"apiVersion"`
	Type       string                 `json:"type"`
	Metadata   *Metadata              `json:"metadata,omitempty"`
	Prop       map[string]interface{} `json:"-"`
	Decorators map[string]interface{} `json:"-"`
}

type Output struct {
	Name       string                 `json:"-"`
	Type       string                 `json:"type"`
	Metadata   *Metadata              `json:"metadata,omitempty"`
	Value      interface{}            `json:"value"`
	Decorators map[string]interface{} `json:"-"`
}

type Module struct {
	Name        string                 `json:"name"`
	Path        string                 `json:"path"`
	Description string                 `json:"description"`
	Decorators  map[string]interface{} `json:"-"`
}

type Prop struct {
	Prop map[string]interface{}
}

type SuperProp map[string]interface{}

type Property struct {
	Description map[string]interface{} `json:"description,omitempty"`
	Properties  []*Property            `json:"properties,omitempty"`
}

type AbsoluteParent struct {
	Allowed  map[string]interface{}
	Resource *Resource
	Module   *Module
	Variable *Variable
}

type Type struct {
	Name          string        `json:"-"`
	Type          string        `json:"type"`
	AllowedValues []interface{} `json:"allowedValues,omitempty"`
	Items         []interface{} `json:"items,omitempty"`
}

func newJSONBicep() *JSONBicep {
	return &JSONBicep{
		Type:      map[string]Type{},
		Params:    map[string]Param{},
		Variables: []Variable{},
		Resources: []Resource{},
		Outputs:   []Output{},
		Modules:   []Module{},
		Metadata:  map[string]string{},
		Lines:     map[string]model.LineObject{},
	}
}

func (res *Resource) MarshalJSON() ([]byte, error) {
	resourceMap := res.Prop
	resourceMap["apiVersion"] = res.APIVersion

	if res.Metadata != nil {
		resourceMap["metadata"] = res.Metadata
	}

	resourceMap["type"] = res.Type
	if res.Decorators[stringSecure] != nil {
		isSecure := res.Decorators[stringSecure].(bool)
		if isSecure {
			resourceMap["type"] = stringSecure + res.Type
		}
	}
	res.Decorators[stringSecure] = nil

	return json.Marshal(resourceMap)
}

func (jsonBicep *JSONBicep) MarshalJSON() ([]byte, error) {
	outputs := map[string]map[string]interface{}{}
	params := map[string]map[string]interface{}{}
	variables := map[string]interface{}{}

	for _, output := range jsonBicep.Outputs {
		tempOutput := map[string]interface{}{}
		tempOutput["type"] = output.Type
		if output.Decorators[stringSecure] != nil {
			isSecure := output.Decorators[stringSecure].(bool)
			if isSecure {
				tempOutput["type"] = stringSecure + output.Type
			}
		}
		output.Decorators[stringSecure] = nil
		tempOutput["metadata"] = output.Metadata
		tempOutput["value"] = output.Value

		for decorator, value := range output.Decorators {
			if !(value == "" || value == nil) {
				tempOutput[decorator] = value
			}
		}

		outputs[output.Name] = tempOutput
	}

	for _, param := range jsonBicep.Params {
		tempParam := map[string]interface{}{}
		tempParam["type"] = param.Type
		if param.Decorators[stringSecure] != nil {
			isSecure := param.Decorators[stringSecure].(bool)
			if isSecure {
				tempParam["type"] = stringSecure + param.Type
			}
		}
		param.Decorators[stringSecure] = nil
		if param.DefaultValue != "" {
			tempParam["defaultValue"] = param.DefaultValue
		}
		tempParam["metadata"] = param.Metadata

		for decorator, value := range param.Decorators {
			if !(value == "" || value == nil) {
				tempParam[decorator] = value
			}
		}

		params[param.Name] = tempParam
	}

	for _, variable := range jsonBicep.Variables {
		tempVar := map[string]interface{}{}
		if variable.Prop != nil {
			for prop, value := range variable.Prop {
				if !(value == "" || value == nil) {
					tempVar[prop] = value
				}
			}
			variables[variable.Name] = tempVar
		} else {
			variables[variable.Name] = variable.Value
		}
	}

	type JSONBicepAlias JSONBicep
	return json.Marshal(&struct {
		*JSONBicepAlias
		Outputs   map[string]map[string]interface{} `json:"outputs"`
		Params    map[string]map[string]interface{} `json:"parameters"`
		Variables map[string]interface{}            `json:"variables"`
	}{
		JSONBicepAlias: (*JSONBicepAlias)(jsonBicep),
		Variables:      variables,
		Outputs:        outputs,
		Params:         params,
	})
}

// Convert - converts Bicep file to JSON Bicep template
func Convert(elems []ElemBicep) (file *JSONBicep, err error) {
	var jBicep = newJSONBicep()

	metadata := map[string]string{}
	resources := []Resource{}
	outputs := []Output{}
	params := map[string]Param{}
	variables := []Variable{}

	for _, elem := range elems {
		switch elem.Type {
		case "resource":
			resources = append(resources, elem.Resource)
		case "param":
			params[elem.Param.Name] = elem.Param
		case "output":
			outputs = append(outputs, elem.Output)
		case "metadata":
			metadata[elem.Metadata.Name] = elem.Metadata.Description
		case "variable":
			variables = append(variables, elem.Variable)
		}
	}

	jBicep.Resources = resources
	jBicep.Params = params
	jBicep.Outputs = outputs
	jBicep.Metadata = metadata
	jBicep.Variables = variables

	return jBicep, nil
}

// const kicsLinesKey = "_kics_"
