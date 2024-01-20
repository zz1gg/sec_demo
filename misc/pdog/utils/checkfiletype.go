package utils

import (
	"github.com/h2non/filetype"
	"io/ioutil"
)

type Ext int

const (
	Unknown Ext = iota
	office      //[doc|docx|xlsx|ppt]
	pdf
	exe
	elf
)

//returns the file name extension used by path
func CheckFileType(target string) Ext {
	buf, _ := ioutil.ReadFile(target)

	kind, _ := filetype.Match(buf)

	//switch path.Ext(target){
	switch kind.Extension {
	case "doc":
		//log.Println("The File is doc document...")
		return office
	case "docx":
		//log.Fatalf("The File is docx  document...")
		return office
	case "xlsx":
		//log.Fatalf("The File is Office Excel document...")
		return office
	case "ppt":
		//log.Fatalf("The File is PPT document...")
		return office
	case "pptx":
		//log.Fatalf("The File is PPTX document...")
		return office
	case "pdf":
		//log.Fatalf("The File is PDF document...")
		return pdf
	case "exe":
		//log.Fatalf("The File is Windows EXE...")
		return exe
	case "elf":
		//log.Fatalf("The File is Executable Linkable Format...")
		return elf
	default:
		return Unknown
	}
}
