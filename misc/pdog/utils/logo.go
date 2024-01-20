package utils

import (
	"flag"
	"fmt"
	"os"
)

func Useage() {
	fmt.Fprintf(os.Stderr, `PDOG version: PDOG/0.0.1

██████╗ ██████╗  ██████╗  ██████╗ 
██╔══██╗██╔══██╗██╔═══██╗██╔════╝ 
██████╔╝██║  ██║██║   ██║██║  ███╗
██╔═══╝ ██║  ██║██║   ██║██║   ██║
██║     ██████╔╝╚██████╔╝╚██████╔╝
╚═╝     ╚═════╝  ╚═════╝  ╚═════╝ 

`)
	flag.PrintDefaults()
}
