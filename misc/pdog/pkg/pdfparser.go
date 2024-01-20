package pkg

import (
	_ "bytes"
	"fmt"
	"pdog/internal/metadata"
)

type PDFInfos struct {
	//XMLName  xml.Name `xml:"xmpmeta"`
	Author   string `xml:"RDF>Description>creator"`
	Creator  string `xml:"RDF>Description>CreatorTool"`
	Producer string `xml:"RDF>Description>Producer"`
}

//var XMLName, Author, Creator, Producer string

func pdfparser(target string) {
	info, err := metadata.NewPropertiesFromPDFDoc(target)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(info)
	//fmt.Println(info[1])
	/*
		m := make(map[string]interface{})
		j, _ := json.Marshal(info[1])
		json.Unmarshal(j, &m)
		//fmt.Println(m)
		fmt.Println("Author: ", m["Author"])
		fmt.Println("Creator: ", m["Creator"])
		fmt.Println("Producer: ", m["Producer"])

	*/

}
