package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// This structure represents the json layout for config objects
type ObjectInfoJson struct {
	Access        string   `json:"access"`
	Owner         string   `json:"owner"`
	SrcFile       string   `json:"srcfile"`
	Multiplicity  string   `json:"multiplicity"`
	Accelerated   bool     `json:"accelerated"`
	UsesStateDB   bool     `json:"usesStateDB"`
	AutoCreate    bool     `json:"autoCreate"`
	AutoDiscover  bool     `json:"autoDiscover"`
	LinkedObjects []string `json:"linkedObjects"`
	Parent        string   `json:"parent"`
	ObjName       string   `json:"-"`
	DbFileName    string   `json:"-"`
	AttrList      []string `json:"-"`
}

// This structure represents the a golang Structure for a config object
type ObjectMembersInfo struct {
	VarType      string   `json:"type"`
	IsKey        bool     `json:"isKey"`
	IsArray      bool     `json:"isArray"`
	Description  string   `json:"description"`
	DefaultVal   string   `json:"default"`
	IsDefaultSet bool     `json:"isDefaultSet"`
	Position     int      `json:"position"`
	Selections   []string `json:"selections"`
	QueryParam   string   `json:"queryparam"`
	Accelerated  bool     `json:"accelerated"`
	Min          int      `json:"min"`
	Max          int      `json:"max"`
	Len          int      `json:"len"`
	UsesStateDB  bool     `json:"usesStateDB"`
	AutoCreate   bool     `json:"autoCreate"`
	AutoDiscover bool     `json:"autoDiscover"`
	Parent       string   `json:"-"` //`json:"parent"`
	IsParentSet  bool     `json:"-"` //`json:"isParentSet"`
	Unit         string   `json:"unit"`
}

type ObjectMemberAndInfo struct {
	ObjectMembersInfo
	MemberName string
}

// This structure represents the objects that are generated directly from go files instead of yang models
type RawObjSrcInfo struct {
	Owner string `json:"owner"`
}

func main() {
	fset := token.NewFileSet() // positions are relative to fset
	base := os.Getenv("SR_CODE_BASE")
	if len(base) <= 0 {
		fmt.Println(" Environment Variable SR_CODE_BASE has not been set")
		return
	}

	//
	// Create a directory to store all the temporary files
	//
	dirStore := base + "/reltools/codegentools/._genInfo/"
	//os.Mkdir(dirStore, 0777)
	listingFile := dirStore + "generatedGoFiles.txt"

	listingsFd, err := os.OpenFile(listingFile, os.O_RDWR|os.O_APPEND+os.O_CREATE, 0660)
	if err != nil {
		fmt.Println("Failed to open the file", listingFile)
		return
	}
	defer listingsFd.Close()

	processConfigObjects(fset, base, listingsFd, dirStore)
	processActionObjects(fset, base, listingsFd, dirStore)
}

func processConfigObjects(fset *token.FileSet, base string, listingsFd *os.File, dirStore string) {
	var goSrcsMap map[string]RawObjSrcInfo
	var objMap map[string]ObjectInfoJson

	objJsonFile := base + "/snaproute/src/models/objects/genObjectConfig.json"
	objFileBase := base + "/snaproute/src/models/objects/"

	//
	// Files generated from yang models are already listed in right format in genObjectConfig.json
	// However in some cases we have only go objects. Read the goObjInfo.json file and generate a similar
	// structure here.
	//
	goObjSources := base + "/snaproute/src/models/objects/goObjInfo.json"

	bytes, err := ioutil.ReadFile(goObjSources)
	if err != nil {
		fmt.Println("Error in reading Object configuration file", goObjSources)
		return
	}
	err = json.Unmarshal(bytes, &goSrcsMap)
	if err != nil {
		fmt.Printf("Error in unmarshaling data from ", goObjSources, err)
	}

	for goSrcFile, ownerName := range goSrcsMap {
		generateHandCodedObjectsInformation(listingsFd, objFileBase, goSrcFile, ownerName.Owner)
	}

	bytes, err = ioutil.ReadFile(objJsonFile)
	if err != nil {
		fmt.Println("Error in reading Object json file", objJsonFile)
		return
	}
	err = json.Unmarshal(bytes, &objMap)
	if err != nil {
		fmt.Printf("Error in unmarshaling data from ", objJsonFile, err)
	}

	parentChild := make(map[string][]string, 1)
	childParent := make(map[string]string, 1)
	for name, obj := range objMap {
		obj.ObjName = name
		srcFile := objFileBase + obj.SrcFile
		f, err := parser.ParseFile(fset, srcFile, nil, parser.ParseComments)
		if err != nil {
			fmt.Println("Failed to parse input file ", srcFile, err)
			return
		}

		for _, dec := range f.Decls {
			tk, ok := dec.(*ast.GenDecl)
			if ok {
				for _, spec := range tk.Specs {
					switch spec.(type) {
					case *ast.TypeSpec:
						typ := spec.(*ast.TypeSpec)
						str, ok := typ.Type.(*ast.StructType)
						if ok && name == typ.Name.Name {
							membersInfo := generateMembersInfoForAllObjects(str, dirStore+typ.Name.Name+"Members.json")
							for _, val := range membersInfo {
								if val.UsesStateDB == true {
									obj.UsesStateDB = true
								}
								if val.AutoCreate == true {
									obj.AutoCreate = true
								}
								if val.AutoDiscover == true {
									obj.AutoDiscover = true
								}
								if val.IsParentSet {
									// Set parent to true when auto create is set
									// Temporarily store parent child into a map...
									//fmt.Println("Child:", typ.Name.Name, "Parent:", val.Parent)
									pEntry := parentChild[val.Parent]
									pEntry = append(pEntry, typ.Name.Name)
									parentChild[val.Parent] = pEntry
									childParent[typ.Name.Name] = val.Parent
								}
							}
							if strings.ContainsAny(obj.Access, "rw") {
								obj.DbFileName = objFileBase + "gen_" + typ.Name.Name + "dbif.go"
								listingsFd.WriteString(obj.DbFileName + "\n")
								obj.WriteDBFunctions(str, membersInfo, objMap)
							}
						}
					}
				}
			}
		}
	}

	// Update genObjectConfig.json file with linkedObjects information...
	addLinkedObjectToGenObjConfig(parentChild, childParent, objMap, objJsonFile)
	objectsByOwner := make(map[string][]ObjectInfoJson, 1)
	for name, obj := range objMap {
		obj.ObjName = name
		objectsByOwner[obj.Owner] = append(objectsByOwner[obj.Owner], obj)
	}

	objectsPackage := "objects"
	generateSerializers(listingsFd, objFileBase, dirStore, objectsByOwner, objectsPackage)
	genJsonSchema(dirStore, objectsByOwner)
}

func processActionObjects(fset *token.FileSet, base string, listingsFd *os.File, dirStore string) {
	var actionMap map[string]ObjectInfoJson
	var goActionSrcsMap map[string]RawObjSrcInfo

	actionJsonFile := base + "/snaproute/src/models/actions/genObjectAction.json"
	actionFileBase := base + "/snaproute/src/models/actions/"
	goActionSources := base + "/snaproute/src/models/actions/goActionInfo.json"

	bytes, err := ioutil.ReadFile(goActionSources)
	if err != nil {
		fmt.Println("Error in reading action object file", goActionSources)
		return
	}
	err = json.Unmarshal(bytes, &goActionSrcsMap)
	if err != nil {
		fmt.Printf("Error in unmarshaling data from ", goActionSources, err)
	}

	for goSrcFile, ownerName := range goActionSrcsMap {
		generateHandCodedActionsInformation(listingsFd, actionFileBase, goSrcFile, ownerName.Owner)
	}

	bytes, err = ioutil.ReadFile(actionJsonFile)
	if err != nil {
		fmt.Println("Error in reading Object action json file", actionJsonFile)
		return
	}
	err = json.Unmarshal(bytes, &actionMap)
	if err != nil {
		fmt.Printf("Error in unmarshaling data from ", actionJsonFile, err)
	}

	for name, action := range actionMap {
		action.ObjName = name
		srcFile := actionFileBase + action.SrcFile
		f, err := parser.ParseFile(fset, srcFile, nil, parser.ParseComments)
		if err != nil {
			fmt.Println("Failed to parse input file ", srcFile, err)
			return
		}

		for _, dec := range f.Decls {
			tk, ok := dec.(*ast.GenDecl)
			if ok {
				for _, spec := range tk.Specs {
					switch spec.(type) {
					case *ast.TypeSpec:
						typ := spec.(*ast.TypeSpec)
						str, ok := typ.Type.(*ast.StructType)
						if ok && name == typ.Name.Name {
							membersInfo := generateMembersInfoForAllObjects(str, dirStore+typ.Name.Name+"Members.json")
							for _, val := range membersInfo {
								if val.UsesStateDB == true {
									action.UsesStateDB = true
								}
								if val.AutoCreate == true {
									action.AutoCreate = true
								}
								if val.AutoDiscover == true {
									action.AutoDiscover = true
								}
							}
							if strings.ContainsAny(action.Access, "rw") {
								action.DbFileName = actionFileBase + "gen_" + typ.Name.Name + "dbif.go"
								listingsFd.WriteString(action.DbFileName + "\n")
								action.WriteDBFunctions(str, membersInfo, actionMap)
							}
						}
					}
				}
			}
		}
	}
	actionsByOwner := make(map[string][]ObjectInfoJson, 1)
	for name, action := range actionMap {
		action.ObjName = name
		actionsByOwner[action.Owner] = append(actionsByOwner[action.Owner], action)
	}

	actionsPackage := "actions"
	generateSerializers(listingsFd, actionFileBase, dirStore, actionsByOwner, actionsPackage)
	genJsonSchema(dirStore, actionsByOwner)
}

func addLinkedObjectToGenObjConfig(parentChild map[string][]string, childParent map[string]string,
	objMap map[string]ObjectInfoJson, objJsonFile string) {
	for key, value := range parentChild {
		entry, exists := objMap[key]
		if exists {
			entry.LinkedObjects = append(entry.LinkedObjects, value...)
			objMap[key] = entry
		}
	}

	for key, value := range childParent {
		entry, exists := objMap[key]
		if exists {
			entry.Parent = value
			objMap[key] = entry
		}
	}
	lines, err := json.MarshalIndent(objMap, "", " ")
	if err != nil {
		fmt.Println("Error is ", err)
	} else {
		genFile, err := os.Create(objJsonFile)
		if err != nil {
			fmt.Println("Failed to open the file", objJsonFile)
			return
		}
		defer genFile.Close()
		genFile.WriteString(string(lines))
	}
}

func getObjectMemberInfo(objMap map[string]ObjectInfoJson, objName string) (membersInfo map[string]ObjectMembersInfo) {
	fset := token.NewFileSet() // positions are relative to fset
	base := os.Getenv("SR_CODE_BASE")
	if len(base) <= 0 {
		fmt.Println(" Environment Variable SR_CODE_BASE has not been set")
		return membersInfo
	}
	objFileBase := base + "/snaproute/src/models/objects"
	for name, obj := range objMap {
		if objName == name {
			obj.ObjName = name
			srcFile := objFileBase + obj.SrcFile
			f, err := parser.ParseFile(fset,
				srcFile,
				nil,
				parser.ParseComments)

			if err != nil {
				fmt.Println("Failed to parse input file ", srcFile, err)
				return
			}

			for _, dec := range f.Decls {
				tk, ok := dec.(*ast.GenDecl)
				if ok {
					for _, spec := range tk.Specs {
						switch spec.(type) {
						case *ast.TypeSpec:
							typ := spec.(*ast.TypeSpec)
							str, ok := typ.Type.(*ast.StructType)
							if ok && name == typ.Name.Name {
								membersInfo = generateMembersInfoForAllObjects(str, "")
								return membersInfo
							}
						}
					}
				}
			}
		}
	}
	return membersInfo
}

var reg = regexp.MustCompile("[`\"]")
var alphas = regexp.MustCompile("[^A-Za-z]")

func getSpecialTagsForAttribute(attrTags string, attrInfo *ObjectMembersInfo) {
	tags := reg.ReplaceAllString(attrTags, "")
	splits := strings.Split(tags, ",")
	for _, part := range splits {
		keys := strings.Split(part, ":")
		for idx, key := range keys {
			key = alphas.ReplaceAllString(key, "")
			switch key {
			case "SNAPROUTE":
				attrInfo.IsKey = true
			case "DESCRIPTION":
				attrInfo.Description = strings.TrimSpace(keys[idx+1])
			case "SELECTION":
				tmpSlice := strings.Split(keys[idx+1], "/")
				for _, val := range tmpSlice {
					attrInfo.Selections = append(attrInfo.Selections, strings.TrimSpace(val))
				}
			case "DEFAULT":
				attrInfo.DefaultVal = strings.TrimSpace(keys[idx+1])
				attrInfo.IsDefaultSet = true
			case "ACCELERATED":
				attrInfo.Accelerated = true
			case "MIN":
				attrInfo.Min, _ = strconv.Atoi(keys[idx+1])
			case "MAX":
				attrInfo.Max, _ = strconv.Atoi(strings.TrimSpace(keys[idx+1]))
			case "RANGE":
				attrInfo.Min, _ = strconv.Atoi(keys[idx+1])
				attrInfo.Max, _ = strconv.Atoi(keys[idx+1])
			case "STRLEN":
				attrInfo.Len, _ = strconv.Atoi(keys[idx+1])
			case "QPARAM":
				attrInfo.QueryParam = keys[idx+1]
			case "USESTATEDB":
				attrInfo.UsesStateDB = true
			case "AUTOCREATE":
				attrInfo.AutoCreate = true
			case "AUTODISCOVER":
				attrInfo.AutoDiscover = true
			case "PARENT":
				attrInfo.Parent = strings.TrimSpace(keys[idx+1])
				attrInfo.IsParentSet = true
			case "UNIT":
				attrInfo.Unit = strings.TrimSpace(keys[idx+1])
			}
		}
	}
	return
}
func generateMembersInfoForAllObjects(str *ast.StructType, objJsonFileName string) map[string]ObjectMembersInfo {
	// Write Skeleton of the structure in json.
	//This would help later python scripts to understand the structure
	var objMembers map[string]ObjectMembersInfo
	objMembers = make(map[string]ObjectMembersInfo, 1)
	var fdHdl *os.File
	var err error
	if objJsonFileName != "" {
		fdHdl, err = os.Create(objJsonFileName)
		if err != nil {
			fmt.Println("Failed to open the file", objJsonFileName)
			return nil
		}
		defer fdHdl.Close()
	}

	for idx, fld := range str.Fields.List {
		if fld.Names != nil {
			varName := fld.Names[0].String()
			switch fld.Type.(type) {
			case *ast.ArrayType:
				arrayInfo := fld.Type.(*ast.ArrayType)
				info := ObjectMembersInfo{}
				info.IsArray = true
				info.Position = idx
				objMembers[varName] = info
				idntType := arrayInfo.Elt.(*ast.Ident)
				varType := idntType.String()
				info.VarType = varType
				objMembers[varName] = info
				if fld.Tag != nil {
					getSpecialTagsForAttribute(fld.Tag.Value, &info)
				}
				objMembers[varName] = info
			case *ast.Ident:
				info := ObjectMembersInfo{}
				if fld.Tag != nil {
					getSpecialTagsForAttribute(fld.Tag.Value, &info)
				}
				idntType := fld.Type.(*ast.Ident)
				varType := idntType.String()
				info.VarType = varType
				info.Position = idx
				objMembers[varName] = info
			}
		}
	}
	lines, err := json.MarshalIndent(objMembers, "", " ")
	if err != nil {
		fmt.Println("Error in converting to Json", err)
	} else {
		if fdHdl != nil {
			fdHdl.WriteString(string(lines))
		}
	}
	return objMembers
}

func generateHandCodedObjectsInformation(listingsFd *os.File, objFileBase string, srcFile string, owner string) error {
	var objMap map[string]ObjectInfoJson
	objMap = make(map[string]ObjectInfoJson, 1)

	// First read the existing objects
	genObjInfoFile := objFileBase + "genObjectConfig.json"

	bytes, err := ioutil.ReadFile(genObjInfoFile)
	if err != nil {
		fmt.Println("Error in reading Object configuration file", genObjInfoFile)
		return err
	}
	err = json.Unmarshal(bytes, &objMap)
	if err != nil {
		fmt.Printf("Error in unmarshaling data from ", genObjInfoFile, err)
	}

	fset := token.NewFileSet() // positions are relative to fset

	// Now read the contents of Hand coded Go structures
	f, err := parser.ParseFile(fset, objFileBase+srcFile, nil, parser.ParseComments)
	if err != nil {
		fmt.Println("Failed to parse input file ", srcFile, err)
		return err
	}

	for _, dec := range f.Decls {
		tk, ok := dec.(*ast.GenDecl)
		if ok {
			for _, spec := range tk.Specs {
				switch spec.(type) {
				case *ast.TypeSpec:
					obj := ObjectInfoJson{}
					obj.SrcFile = srcFile
					obj.Owner = owner
					typ := spec.(*ast.TypeSpec)
					str, ok := typ.Type.(*ast.StructType)
					if ok == true {
						for _, fld := range str.Fields.List {
							if fld.Names != nil {
								switch fld.Type.(type) {
								case *ast.Ident:
									if fld.Tag != nil {
										if strings.Contains(fld.Tag.Value, "SNAPROUTE") {
											for _, elem := range strings.Split(fld.Tag.Value, ",") {
												splits := strings.Split(elem, ":")
												switch strings.Trim(splits[0], " ") {
												case "ACCESS":
													obj.Access = strings.Trim(splits[1], "\"")

												case "MULTIPLICITY":
													tmpString := strings.Trim(splits[1], "`")
													obj.Multiplicity = strings.Trim(tmpString, "\"")

												case "ACCELERATED":
													obj.Accelerated = true

												case "USESTATEDB":
													obj.UsesStateDB = true
												case "AUTOCREATE":
													obj.AutoCreate = true
												case "AUTODISCOVER":
													obj.AutoDiscover = true
												}
											}
										}
									}
								}
							}
						}
						objMap[typ.Name.Name] = obj
					}
				}
				lines, err := json.MarshalIndent(objMap, "", " ")
				if err != nil {
					fmt.Println("Error is ", err)
				} else {
					genFile, err := os.Create(genObjInfoFile)
					if err != nil {
						fmt.Println("Failed to open the file", genObjInfoFile)
						return err
					}
					defer genFile.Close()
					genFile.WriteString(string(lines))
				}
			}
		}
	}
	return nil
}

func generateHandCodedActionsInformation(listingsFd *os.File, actionFileBase string, srcFile string, owner string) error {
	var actionMap map[string]ObjectInfoJson
	actionMap = make(map[string]ObjectInfoJson, 1)

	// First read the existing objects
	genActionInfoFile := actionFileBase + "genObjectAction.json"

	bytes, err := ioutil.ReadFile(genActionInfoFile)
	if err == nil {
		err = json.Unmarshal(bytes, &actionMap)
		if err != nil {
			fmt.Printf("Error in unmarshaling data from ", genActionInfoFile, err)
		}
	}

	fset := token.NewFileSet() // positions are relative to fset

	// Now read the contents of Hand coded Go structures
	f, err := parser.ParseFile(fset, actionFileBase+srcFile, nil, parser.ParseComments)
	if err != nil {
		fmt.Println("Failed to parse input file ", srcFile, err)
		return err
	}

	for _, dec := range f.Decls {
		tk, ok := dec.(*ast.GenDecl)
		if ok {
			for _, spec := range tk.Specs {
				switch spec.(type) {
				case *ast.TypeSpec:
					typ := spec.(*ast.TypeSpec)
					action := ObjectInfoJson{}
					action.SrcFile = srcFile
					action.Owner = owner
					action.Access = "x"
					actionMap[typ.Name.Name] = action
				}

				lines, err := json.MarshalIndent(actionMap, "", " ")
				if err != nil {
					fmt.Println("Error is ", err)
				} else {
					genFile, err := os.Create(genActionInfoFile)
					if err != nil {
						fmt.Println("Failed to open the file", genActionInfoFile)
						return err
					}
					defer genFile.Close()
					genFile.WriteString(string(lines))
				}
			}
		}
	}
	return nil
}

func generateSerializers(listingsFd *os.File, objFileBase string, dirStore string, objectsByOwner map[string][]ObjectInfoJson, packageName string) error {
	for owner, objList := range objectsByOwner {
		if len(objList) > 0 {
			srcFile := objList[0].SrcFile
			//if owner != "lacpd" { //|| owner != "ospfd" {
			generateUnmarshalFcn(listingsFd, objFileBase, dirStore, owner, srcFile, objList, packageName)
			//}
		}
	}
	return nil
}

func generateUnmarshalFcn(listingsFd *os.File, objFileBase string, dirStore string, ownerName string, srcFile string, objList []ObjectInfoJson, packageName string) error {
	var marshalFcnsLine []string
	var objIf string
	if packageName == "actions" {
		objIf = "ActionObj"
	} else {
		objIf = "ConfigObj"
	}
	marshalFcnFile := objFileBase + "gen_" + ownerName + "Objects_serializer.go"
	marshalFcnFd, err := os.Create(marshalFcnFile)
	if err != nil {
		fmt.Println("Failed to open the file", marshalFcnFile)
		return err
	}
	defer marshalFcnFd.Close()
	for _, obj := range objList {
		//fmt.Println("Object Name for Unmarshal ", obj.ObjName)
		listingsFd.WriteString(marshalFcnFile + "\n")
		if strings.Contains(obj.Access, "w") || strings.Contains(obj.Access, "r") || strings.Contains(obj.Access, "x") {
			if packageName == "actions" {
				marshalFcnsLine = append(marshalFcnsLine, "\nfunc (obj "+obj.ObjName+") UnmarshalAction(body []byte) ("+objIf+", error) {\n")
			} else {
				marshalFcnsLine = append(marshalFcnsLine, "\nfunc (obj "+obj.ObjName+") UnmarshalObject(body []byte) ("+objIf+", error) {\n")

			}
			marshalFcnsLine = append(marshalFcnsLine, "var err error \n")

			// Check all attributes and write default constructor
			membersInfoFile := dirStore + obj.ObjName + "Members.json"
			var objMembers map[string]ObjectMembersInfo
			objMembers = make(map[string]ObjectMembersInfo, 1)
			bytes, err := ioutil.ReadFile(membersInfoFile)
			if err != nil {
				fmt.Println("Error in reading Object configuration file", membersInfoFile)
				return err
			}
			err = json.Unmarshal(bytes, &objMembers)
			if err != nil {
				fmt.Printf("Error in unmarshaling data from \n", membersInfoFile, err)
				return err
			}
			for attrName, attrInfo := range objMembers {
				if attrInfo.IsDefaultSet {
					if attrInfo.VarType == "string" {
						marshalFcnsLine = append(marshalFcnsLine, "obj."+attrName+" = "+"\""+attrInfo.DefaultVal+"\""+"\n")
					} else if attrInfo.IsArray {
						marshalFcnsLine = append(marshalFcnsLine, "obj."+attrName+"= make([]"+attrInfo.VarType+", 0)"+"\n")
					} else {
						marshalFcnsLine = append(marshalFcnsLine, "obj."+attrName+" = "+attrInfo.DefaultVal+"\n")
					}
				}
			}
			marshalFcnsLine = append(marshalFcnsLine, `
													if len(body) > 0 {
													    if err = json.Unmarshal(body, &obj); err != nil {
													         fmt.Println("###  called, unmarshal failed", obj, err)
													      }
													   }
													   return obj, err
													}
													`)
			//fmt.Println(marshalFcnsLine)

		}
		if strings.Contains(obj.Access, "w") || strings.Contains(obj.Access, "r") {
			marshalFcnsLine = append(marshalFcnsLine, "\nfunc (obj "+obj.ObjName+") UnmarshalObjectData(queryMap map[string][]string) (ConfigObj, error) {\n")
			marshalFcnsLine = append(marshalFcnsLine, "\nretObj := "+obj.ObjName+"{}")
			marshalFcnsLine = append(marshalFcnsLine, `
		        objVal := reflect.ValueOf(&retObj)
		        for key, val := range queryMap {
		                field := objVal.Elem().FieldByName(key)
		                if field.CanSet() {
		                        switch field.Kind() {
		                        case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		                                i, _ := strconv.ParseInt(val[0], 10, 64) 
		                                field.SetInt(i)
		                        case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		                                ui, _ := strconv.ParseUint(val[0], 10, 64) 
		                                field.SetUint(ui)
		                        case reflect.Float64:
		                                f, _ := strconv.ParseFloat(val[0], 64) 
		                                field.SetFloat(f)
		                        case reflect.Bool:
		                                b, _ := strconv.ParseBool(val[0])
                		                field.SetBool(b)
		                        case reflect.String:
                		                field.SetString(val[0])
		                        }
		                }
		        }
		        return retObj, nil 
		}
		`)
		}
	}
	if len(marshalFcnsLine) > 0 {
		packageLine := "package " + packageName
		marshalFcnFd.WriteString(packageLine)
		if packageName == "actions" {
			marshalFcnFd.WriteString(`

			import (
			   "encoding/json"
			   "fmt"
			)`)
		} else {
			marshalFcnFd.WriteString(`

			import (
			   "encoding/json"
			   "fmt"
 		           "reflect"
		           "strconv"
			)`)
		}

		for _, marshalLine := range marshalFcnsLine {
			marshalFcnFd.WriteString(string(marshalLine))
		}
	}
	return nil
}
