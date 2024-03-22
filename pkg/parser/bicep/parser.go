package bicep

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Checkmarx/kics/pkg/model"
	"github.com/Checkmarx/kics/pkg/parser/bicep/converter"
)

// Parser - parser for Bicep files
type Parser struct {
}

// Parse - parses bicep to JSON_Bicep template (json file)
func (p *Parser) Parse(_ string, fileContent []byte) ([]model.Document, []int, error) {
	doc := model.Document{}
	elems, err := parserBicepFile(fileContent)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing bicep file on parse function: %w", err)
	}

	jElem, _ := converter.Convert(elems)

	elemListBytes, err := json.Marshal(jElem)
	if err != nil {
		return nil, nil, fmt.Errorf("error marshaling bicep file on parse function: %w", err)
	}

	err = json.Unmarshal(elemListBytes, &doc)
	if err != nil {
		return nil, nil, fmt.Errorf("error unmarshaling bicep file on parse function: %w", err)
	}

	return []model.Document{doc}, nil, nil
}

// parse the bicep file returning a list of elemBicep struct and an error
func parserBicepFile(bicepContent []byte) ([]converter.ElemBicep, error) {
	reader := bytes.NewReader(bicepContent)
	scanner := bufio.NewScanner(reader)

	var absoluteParent converter.AbsoluteParent
	elems := []converter.ElemBicep{}
	parentsStack := []converter.SuperProp{}
	decorators := map[string]interface{}{}
	tempMap := map[string]interface{}{}

	for scanner.Scan() {
		elem := converter.ElemBicep{}
		line := scanner.Text()

		if line == "" {
			continue
		}

		fmt.Println(line)

		isNewParentRegex := regexp.MustCompile(`\{`)
		isNewParent := len(isNewParentRegex.FindStringSubmatch(line)) > 0

		isParentClosingRegex := regexp.MustCompile(`\}`)
		isParentClosing := len(isParentClosingRegex.FindStringSubmatch(line)) > 0

		isOpeningArrayRegex := regexp.MustCompile(`\[`)
		isOpeningArray := len(isOpeningArrayRegex.FindStringSubmatch(line)) > 0

		isClosingArrayRegex := regexp.MustCompile(`\]`)
		isClosingArray := len(isClosingArrayRegex.FindStringSubmatch(line)) > 0

		isClosingAllowedRegex := regexp.MustCompile(`\)`)
		isClosingAllowed := len(isClosingAllowedRegex.FindStringSubmatch(line)) > 0

		targetScope := parseTargetScope(line)
		if targetScope != "" {
			elem.TargetScope = targetScope
			elem.Type = "targetScope"
			elems = append(elems, elem)
			continue
		}

		metadata := parseMetadata(line)
		if metadata != nil {
			elem.Metadata = *metadata
			elem.Type = "metadata"
			elems = append(elems, elem)
			continue
		}

		isMetadata, isSecure, isAllowed := parseDecorator(decorators, line)
		if isMetadata {
			continue
		}
		if isSecure {
			decorators["secure"] = true
			continue
		} else if isAllowed {
			allowed := map[string]interface{}{}
			var values map[string]interface{}

			if isClosingArray {
				vals := strings.Replace(line, "@allowed(", "", 1)
				vals = strings.Replace(vals, "[", "", 1)
				vals = strings.Replace(vals, "]", "", 1)
				decorators["allowed"] = strings.Split(vals, ",")
				continue
			}

			values = map[string]interface{}{"values": []interface{}{}}
			parentsStack = append(parentsStack, values)
			absoluteParent.Allowed = allowed
			absoluteParent.Variable = nil
			absoluteParent.Module = nil
			absoluteParent.Resource = nil

			continue
		}

		variable, isSingle, isArray := parseVariable(line, elems)
		if variable != nil {
			if isSingle {
				elem.Variable = *variable
				elem.Type = "variable"
				elems = append(elems, elem)
			} else {
				decorators = map[string]interface{}{}
				tempMap = map[string]interface{}{}
				if isArray {
					varProp := map[string]interface{}{"values": []interface{}{}}
					parentsStack = append(parentsStack, varProp)
				}
				absoluteParent.Variable = variable
				absoluteParent.Allowed = nil
				absoluteParent.Module = nil
				absoluteParent.Resource = nil
			}
			continue
		}

		resource := parseResource(decorators, line)
		if resource != nil {
			elem.Resource = *resource
			elem.Type = "resource"

			decorators = map[string]interface{}{}
			absoluteParent.Resource = resource
			absoluteParent.Allowed = nil
			absoluteParent.Module = nil
			absoluteParent.Variable = nil
			continue
		}

		param := parseParam(decorators, line)
		if param != nil {
			decorators = map[string]interface{}{}
			elem.Param = *param
			elem.Type = "param"
			elems = append(elems, elem)
			continue
		}

		output := parseOutput(decorators, line)
		if output != nil {
			decorators = map[string]interface{}{}
			elem.Output = *output
			elem.Type = "output"
			elems = append(elems, elem)
			continue
		}

		inlineArray := parseInlineArray(line)
		if inlineArray != nil {
			if len(parentsStack) > 0 {
				addPropToParent(parentsStack, inlineArray)
			} else {
				for k, v := range inlineArray {
					tempMap[k] = v
				}
			}
			continue
		}

		if len(parentsStack) > 1 {
			parent := parentsStack[len(parentsStack)-2]
			added := false
			for index, array := range parent {
				if isParentClosing && array != nil && is_slice(array) {
					var newProp map[string]interface{}
					parentsStack, newProp = popParentsStack(parentsStack)
					for _, val := range newProp {
						array = append(array.([]interface{}), val)
						parentsStack[len(parentsStack)-1][index] = array
					}
					added = true
				}
			}
			if added {
				continue
			}
		}

		prop := parseProp(line, elems)

		if len(parentsStack) > 0 {
			currentParent := parentsStack[len(parentsStack)-1]
			for k, v := range currentParent {
				if is_slice(v) && !isClosingArray && !isNewParent && !isParentClosing && prop == nil {
					arrayElementRegex := regexp.MustCompile(`^ *'?([^']*)`)
					arrayElement := arrayElementRegex.FindStringSubmatch(line)[1]
					temp := append(v.([]interface{}), arrayElement)
					currentParent[k] = temp
					continue
				}
			}
		}

		if isClosingArray {

			if len(parentsStack) == 1 && absoluteParent.Variable != nil && absoluteParent.Variable.IsArray {
				var varProp map[string]interface{}
				parentsStack, varProp = popParentsStack(parentsStack)
				absoluteParent.Variable.Prop = varProp
				elem.Variable = *absoluteParent.Variable
				elem.Type = "variable"
				elems = append(elems, elem)
				absoluteParent.Variable = nil
				tempMap = map[string]interface{}{}

				continue
			}

			var currentProperty map[string]interface{}
			parentsStack, currentProperty = popParentsStack(parentsStack)

			if len(parentsStack) > 0 {
				addPropToParent(parentsStack, currentProperty)

			} else {
				for k, v := range currentProperty {
					tempMap[k] = v
				}
			}
		}

		if isOpeningArray {
			//inicializar array e adicionar ao parentstack no caso de line estar a abrir array
			newProp := converter.SuperProp{}

			for k := range prop {
				newProp[k] = []interface{}{}
			}

			parentsStack = append(parentsStack, newProp)
			continue
		}

		if prop != nil {
			if isNewParent {
				// if !isParentClosing {
				newProp := converter.SuperProp{}

				for k := range prop {
					newProp[k] = converter.SuperProp{}
				}

				parentsStack = append(parentsStack, newProp)
				// }
			} else {
				if len(parentsStack) > 0 {
					//adicionar prop ao parent se o parentstack não estiver vazio
					parent := parentsStack[len(parentsStack)-1]
					for name, val := range parent {
						if is_slice(val) {
							tempArr := append(val.([]interface{}), prop)
							parentsStack[len(parentsStack)-1] = map[string]interface{}{name: tempArr}
						} else {
							jigajoga := converter.SuperProp{}
							for k, v := range prop {
								jigajoga[k] = v
							}
							addPropToParent(parentsStack, jigajoga)
						}
					}
				} else {
					// adicionar o prop ao temparray se o parentstack estiver vazio
					for k, v := range prop {
						tempMap[k] = v
					}
				}
			}
			continue
		}

		if isNewParent {
			parent := parentsStack[len(parentsStack)-1]
			var propID string
			for _, arr := range parent {
				propID = strconv.Itoa(len(arr.([]interface{})))
			}

			newParent := map[string]interface{}{propID: converter.SuperProp{}}
			parentsStack = append(parentsStack, newParent)
		}

		if isParentClosing && len(parentsStack) > 1 {
			var currentProperty map[string]interface{}
			parentsStack, currentProperty = popParentsStack(parentsStack)
			addPropToParent(parentsStack, currentProperty)
			continue
		}

		if isParentClosing && len(parentsStack) == 1 {
			currentProperty := parentsStack[0]
			parentsStack = append(parentsStack[:0], parentsStack[1:]...)

			for k, v := range currentProperty {
				tempMap[k] = v
			}

			continue
		}

		if isParentClosing && len(parentsStack) == 0 {
			if absoluteParent.Resource != nil {
				absoluteParent.Resource.Prop = tempMap
				elem.Resource = *absoluteParent.Resource
				elem.Type = "resource"
				elems = append(elems, elem)
				absoluteParent.Resource = nil
				tempMap = map[string]interface{}{}
			}
			if absoluteParent.Variable != nil {
				absoluteParent.Variable.Prop = tempMap
				elem.Variable = *absoluteParent.Variable
				elem.Type = "variable"
				elems = append(elems, elem)
				absoluteParent.Variable = nil
				tempMap = map[string]interface{}{}
			}

			continue
		}

		if absoluteParent.Allowed != nil && isClosingAllowed {
			absoluteParent.Allowed = nil
			decorators["allowed"] = tempMap["values"]
			tempMap = map[string]interface{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return []converter.ElemBicep{}, fmt.Errorf("error reading bicep file on parserBicepFile function: %w", err)
	}

	return elems, nil
}

func isParamOrVariable(val string, elems []converter.ElemBicep) string {
	paramValueRegex := regexp.MustCompile(`([^(]*)\(([^\)]*)\)(.*)`)
	paramValue := paramValueRegex.FindStringSubmatch(val)
	if paramValue != nil {
		return paramValue[1] + "(" + isParamOrVariable(paramValue[2], elems) + ")" + paramValue[3]
	}

	for _, param := range elems {
		if param.Type == "param" {
			if param.Param.Name == val {
				return fmt.Sprintf("parameters('%s')", val)
			}
		}
	}

	return strings.ReplaceAll(val, "'", "")

}

func convertToInitialType(val string, elems []converter.ElemBicep) interface{} {
	boolVal, err := strconv.ParseBool(val)
	if err == nil {
		return boolVal
	}

	intVal, err := strconv.Atoi(val)
	if err == nil {
		return intVal
	}

	return isParamOrVariable(val, elems)

}

func popParentsStack(parentsStack []converter.SuperProp) ([]converter.SuperProp, map[string]interface{}) {
	currentPropertyIndex := len(parentsStack) - 1
	currentProperty := parentsStack[currentPropertyIndex]
	parentsStack = append(parentsStack[:currentPropertyIndex], parentsStack[currentPropertyIndex+1:]...)

	return parentsStack, currentProperty
}

func addPropToParent(parentsStack []converter.SuperProp, prop map[string]interface{}) {
	parent := parentsStack[len(parentsStack)-1]
	var siblings converter.SuperProp
	for k := range parent {
		siblings = parent[k].(converter.SuperProp)
	}
	for k, v := range prop {
		siblings[k] = v
	}
	for k := range parent {
		parent[k] = siblings
	}
}

func is_slice(str interface{}) bool {
	isSlice := false
	if _, ok := str.([]interface{}); ok {
		isSlice = true
	}
	return isSlice
}

// parse targetScope syntax from bicep file
func parseTargetScope(line string) string {
	targetScopeRegex := regexp.MustCompile(`targetScope * = * *'?([^']*)'`)
	matches := targetScopeRegex.FindStringSubmatch(line)

	if matches != nil {
		targetScope := matches[1]
		return targetScope
	}

	return ""
}

// parse Variable syntax from bicep file
func parseVariable(line string, elems []converter.ElemBicep) (parsedVar *converter.Variable, isSingle bool, isArray bool) {
	singleLineVarRegex := regexp.MustCompile(`var +([^ ]*) += +'?(?:([^']*)|(?:\${([^}]*)}))'?`)
	multiLineVarRegex := regexp.MustCompile(`var +([^ ]*) += +{`)
	arrayVarRegex := regexp.MustCompile(`var +([^ ]*) += +\[`)
	// forLineVarRegex := regexp.MustCompile(`for`)
	matchesSingle := singleLineVarRegex.FindStringSubmatch(line)
	matchesMulti := multiLineVarRegex.FindStringSubmatch(line)
	matchesArrayVar := arrayVarRegex.FindStringSubmatch(line)
	// matchFor := forLineVarRegex.FindStringSubmatch(line)

	if matchesSingle != nil {
		name := matchesSingle[1]
		value := matchesSingle[2]
		checkParamRegex := regexp.MustCompile(`(\${[^}]*}|-[^-]*-)`)
		matchesCheckParam := checkParamRegex.FindAllStringSubmatch(value, -1)
		var formattedVar string
		placeholderValues := []string{}
		var placeHolderCount int

		if matchesCheckParam != nil {
			for _, varElem := range matchesCheckParam {
				for index, elem := range varElem {
					if index%2 != 0 {
						if strings.Contains(elem, "${") {
							newVal := strings.Replace(elem, "${", "", 1)
							newVal = strings.Replace(newVal, "}", "", 1)
							newVal = isParamOrVariable(newVal, elems)
							formattedVar = formattedVar + ", " + newVal
							placeholderValues = append(placeholderValues, "{"+strconv.Itoa(placeHolderCount)+"}")
							placeHolderCount++
						} else {
							placeholderValues = append(placeholderValues, elem)
						}
					}
				}
			}

			formattedVar = formattedVar + ")]"

			formatString := "[format('"
			for _, placeHollderValue := range placeholderValues {
				formatString = formatString + placeHollderValue
			}
			formatString = formatString + "'"

			formattedVar = formatString + formattedVar

			return &converter.Variable{Name: name, Value: formattedVar, IsArray: false}, true, false
		} else {
			// matchesCheckParam == nil, object parsing, isSimple is false
			if strings.Contains(value, "{") {
				return &converter.Variable{Name: name, Value: value, IsArray: false}, false, false
			}
			// matchesCheckParam == nil, simple regex, isSimple is true
			return &converter.Variable{Name: name, Value: value, IsArray: false}, true, false
		}
	}

	if matchesMulti != nil {
		name := matchesMulti[1]
		return &converter.Variable{Name: name, IsArray: false}, false, false
	}

	if matchesArrayVar != nil {
		name := matchesArrayVar[1]
		return &converter.Variable{Name: name, IsArray: true}, false, true
	}

	return nil, false, false
}

// parse Metadata syntax from bicep file
func parseMetadata(line string) *converter.Metadata {
	metadataRegex := regexp.MustCompile(`metadata ([^ ]*) * = *'?([^']*)'`)
	matches := metadataRegex.FindStringSubmatch(line)

	if matches != nil {
		name := matches[1]
		value := matches[2]
		return &converter.Metadata{Name: name, Description: value}
	}

	return nil
}

// parse Inline Array syntax from bicep file
func parseInlineArray(line string) map[string]interface{} {
	// metadataRegex := regexp.MustCompile(` *([^ :']*): *\[ *(?:'?([^' ]*)'?) *]`)
	metadataRegex := regexp.MustCompile(` *([^ :']*): *\[(.*?)\]`)
	matches := metadataRegex.FindStringSubmatch(line)

	if matches != nil {
		name := matches[1]
		value := matches[2]

		values := []string{value}

		return map[string]interface{}{name: values}
	}

	return nil
}

// parse Decorator syntax from bicep file
func parseDecorator(decorators map[string]interface{}, line string) (bool, bool, bool) {
	singleDecoratorRegex := regexp.MustCompile(`@(?:sys\.)?([^()]+)\('?([^')]*)'?\)`)
	metadataDecoratorRegex := regexp.MustCompile(`@(?:sys\.)?[description]([^()]+)\('?([^')]*)'?\)`)
	allowedDecoratorRegex := regexp.MustCompile(`@(?:sys\.)?allowed:?\(\[`)
	matchesSingle := singleDecoratorRegex.FindStringSubmatch(line)
	matchesMetadata := metadataDecoratorRegex.FindStringSubmatch(line)
	matchesAllowed := allowedDecoratorRegex.FindStringSubmatch(line)

	// match single line decorators
	if matchesSingle != nil {
		name := matchesSingle[1]
		value := matchesSingle[2]

		switch name {
		case "secure":
			return false, true, false
		case "description":
			var description = make(map[string]interface{})
			description[name] = value
			decorators["metadata"] = map[string]interface{}{name: value}
			return true, false, false
		case "maxLength":
			decorators[name] = value
			return true, false, false
		case "minLength":
			decorators[name] = value
			return true, false, false
		case "maxValue":
			decorators[name] = value
			return true, false, false
		case "minValue":
			decorators[name] = value
			return true, false, false
		}
	}

	// match metadata decorators
	if matchesMetadata != nil {
		tempMetadata := map[string]string{}
		tempMetadata["description"] = matchesMetadata[2]

		decorators["metadata"] = tempMetadata
		return true, false, false
	}

	// match allowed decorators
	if matchesAllowed != nil {
		tempAllowed := []string{}

		decorators["allowed"] = tempAllowed
		return false, false, true
	}

	return false, false, false
}

// parse Resource syntax from bicep file
func parseResource(decorators map[string]interface{}, line string) *converter.Resource {
	resourceRegex := regexp.MustCompile(`^resource\s+(\S+)\s+'(\S+)'\s+=\s+\{\s*`)

	matches := resourceRegex.FindStringSubmatch(line)
	if matches != nil {
		resourceType := strings.Split(matches[2], "@")[0]
		resourceType = strings.ReplaceAll(resourceType, "'", "")

		apiVersion := ""
		apiVersionRegex := regexp.MustCompile(`@(\S+)`)
		apiMatches := apiVersionRegex.FindStringSubmatch(matches[2])
		if len(apiMatches) > 1 {
			apiVersion = apiMatches[1]
		}

		return &converter.Resource{
			APIVersion: apiVersion,
			Type:       resourceType,
			Decorators: decorators,
			// Metadata:   &converter.Metadata{Description: "Description", Name: "test"},
		}
	}

	return nil
}

// parse Param syntax from bicep file
func parseParam(decorators map[string]interface{}, line string) *converter.Param {
	paramRegex := regexp.MustCompile(`^param\s+(\S+)\s+(\S+)\s+=\s+'(.+)'`)
	matches := paramRegex.FindStringSubmatch(line)

	if matches != nil {
		paramName := matches[1]
		paramType := matches[2]
		paramDefaultValue := matches[3]
		return &converter.Param{
			Name:         paramName,
			Type:         paramType,
			DefaultValue: paramDefaultValue,
			Decorators:   decorators,
			// Metadata:     &converter.Metadata{Description: "Description", Name: "test"},
		}
	}

	return nil
}

// parse Output syntax from bicep file
func parseOutput(decorators map[string]interface{}, line string) *converter.Output {
	outputRegex := regexp.MustCompile(`^output\s+(\S+)\s+(\S+)\s+=\s+'(.+)'`)
	matches := outputRegex.FindStringSubmatch(line)
	if matches != nil {
		outputName := matches[1]
		outputType := matches[2]
		outputValue := matches[3]

		return &converter.Output{
			Name:       outputName,
			Type:       outputType,
			Value:      outputValue,
			Decorators: decorators,
			// Metadata:   &converter.Metadata{Description: "Description", Name: "test"},
		}
	}

	return nil
}

func parseProp(line string, elems []converter.ElemBicep) map[string]interface{} {
	// Parse key-value pairs

	// parts := strings.SplitN(line, ":", 2)
	// if len(parts) == 2 {

	propRegex := regexp.MustCompile(`([^: ]*) *: *'?([^']*)'?`)
	matches := propRegex.FindStringSubmatch(line)

	if matches != nil {
		key := strings.TrimSpace(matches[1])
		value := strings.TrimSpace(matches[2])
		convertedValue := convertToInitialType(value, elems)
		var description = make(map[string]interface{})
		description[key] = convertedValue
		return description
	}

	return nil
}

// GetKind returns the kind of the parser
func (p *Parser) GetKind() model.FileKind {
	return model.KindBICEP
}

// SupportedExtensions returns Bicep extensions
func (p *Parser) SupportedExtensions() []string {
	return []string{".bicep"}
}

// SupportedTypes returns types supported by this parser, which are bicep files
func (p *Parser) SupportedTypes() map[string]bool {
	return map[string]bool{"bicep": true, "azureresourcemanager": true}
}

// GetCommentToken return the comment token of Bicep files - #
func (p *Parser) GetCommentToken() string {
	return "//"
}

// StringifyContent converts original content into string formatted version
func (p *Parser) StringifyContent(content []byte) (string, error) {
	return string(content), nil
}

// Resolve resolves bicep files variables
func (p *Parser) Resolve(fileContent []byte, _ string, _ bool) ([]byte, error) {
	return fileContent, nil
}

// GetResolvedFiles returns the list of files that are resolved
func (p *Parser) GetResolvedFiles() map[string]model.ResolvedFile {
	return make(map[string]model.ResolvedFile)
}
