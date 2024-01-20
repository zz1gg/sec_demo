package main

import (
	"log"
	"os"
	"pdog/cmd"
	"pdog/utils"
)

func main() {
	if len(os.Args) < 2 {
		utils.Useage()
	}

	err := cmd.Execute()
	if err != nil {
		log.Fatalf("cmd Execute err: %v", err)
	}
}
