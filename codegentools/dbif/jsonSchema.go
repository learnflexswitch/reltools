package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type KeyInfo struct {
	VarType  string `json:"type"`
	RefTable string `json:"refTable,omitempty"`
	//Min      int    `json:"minLength, omitempty"`
	//Max      int    `json:"maxLength, omitempty"`
}

type TypeInfo struct {
	Key KeyInfo `json:"key"`
}

type ColumnInfo struct {
	Category string   `json:"category"`
	Type     TypeInfo `json:"type"`
}

type TableInfo struct {
	Columns map[string]ColumnInfo `json:"columns"`
	Indexes [][]string            `json:"indexes,omitempty"`
	IsRoot  bool                  `json:"isRoot,omitempty"`
}

type SchemaInfo struct {
	Name    string               `json:"name"`
	Version string               `json:"version"`
	Tables  map[string]TableInfo `json:"tables"`
}

func createSchema(objMap map[string]ObjectMembersInfo, objConfig ObjectInfoJson) TableInfo {
	var ovsColumns map[string]ColumnInfo
	var table TableInfo
	var indexes []string

	ovsColumns = make(map[string]ColumnInfo, len(objMap))

	for name, obj := range objMap {
		info := ColumnInfo{}

		switch objConfig.Access {
		case "r":
			info.Category = "status"
		case "w":
			info.Category = "configuration"
		case "":
			// This is special case for objects that are referenced
			info.Category = "configuration"
		}

		switch obj.VarType {
		case "uint8", "uint16", "uint32", "uint64", "int8", "int16", "int32":
			info.Type.Key.VarType = "integer"
		case "bool":
			info.Type.Key.VarType = "boolean"
		case "string":
			info.Type.Key.VarType = "string"
		default:
			info.Type.Key.VarType = "uuid"
			info.Type.Key.RefTable = obj.VarType
		}
		if obj.IsKey {
			indexes = append(indexes, name)
			table.IsRoot = true
		}
		//@TODO: jgheewala add support for min, max, minInteger, maxInteger, minLength, maxLength
		//info.Min = obj.Min
		//info.Max = obj.Max
		ovsColumns[name] = info
	}

	if len(indexes) > 0 {
		table.Indexes = append(table.Indexes, indexes)
	}
	table.Columns = ovsColumns

	return table

}

const (
	MEMBER_JSON = "Members.json"
)

func writeJson(extSchemaFile string, jsonSchema SchemaInfo) {
	var genFile *os.File
	var err error
	if genFile == nil {
		genFile, err = os.Create(extSchemaFile)
		if err != nil {
			fmt.Println("Failed to open file", err)
			os.Exit(1)
		}
	}
	defer genFile.Close()

	lines, err := json.MarshalIndent(jsonSchema, "", "   ")
	if err != nil {
		fmt.Println("Error in converting to ", err)
	} else {
		if genFile != nil {
			genFile.WriteString(string(lines))
		}
	}
}

// dirStore := base + "/reltools/codegentools/._genInfo/"
func genJsonSchema(dirStore string, objectsByOwner map[string][]ObjectInfoJson) {
	for owner, objList := range objectsByOwner {
		var jsonSchema SchemaInfo
		ovsTables := make(map[string]TableInfo)
		jsonSchema.Name = owner
		jsonSchema.Version = "0.0.1"
		for _, obj := range objList {
			if obj.Access == "x" {
				continue
			}
			jsonFileName := dirStore + obj.ObjName + MEMBER_JSON
			bytes, err := ioutil.ReadFile(jsonFileName)
			if err != nil {
				fmt.Println("Error in reading Object configuration file", jsonFileName,
					"error is", err)
				continue
			}
			var objMap map[string]ObjectMembersInfo
			err = json.Unmarshal(bytes, &objMap)
			if err != nil {
				fmt.Printf("Error in unmarshaling data from ", err)
				continue
			}
			table := createSchema(objMap, obj)
			ovsTables[obj.ObjName] = table
		}
		jsonSchema.Tables = ovsTables
		extSchemaFile := dirStore + owner + ".extschema"
		writeJson(extSchemaFile, jsonSchema)
	}
}
