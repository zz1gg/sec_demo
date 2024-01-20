package main

import (
	"fmt"
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// https://stackoverflow.com/questions/20365286/query-wmi-from-go
func main() {
	err := ole.CoInitialize(0)
	if err != nil {
		return
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		fmt.Println("Error creating WbemScripting.SWbemLocator:", err)
		return
	}
	defer unknown.Release()

	wmiLocator, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		fmt.Println("Error querying WMI locator interface:", err)
		return
	}
	defer wmiLocator.Release()

	// Specify the namespace
	serviceRaw, err := oleutil.CallMethod(wmiLocator, "ConnectServer", nil, "\\root\\SecurityCenter2")
	if err != nil {
		fmt.Println("Error connecting to WMI server:", err)
		return
	}
	service := serviceRaw.ToIDispatch()
	defer service.Release()

	//Get-CimClass -Namespace root\SecurityCenter2
	//Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct
	//AntiSpywareProduct,AntiVirusProduct,FirewallProduct
	// Execute WMI query
	resultRaw, err := oleutil.CallMethod(service, "ExecQuery", "SELECT * FROM AntiVirusProduct")

	if err != nil {
		fmt.Println("Error executing WMI query:", err)
		return
	}
	result := resultRaw.ToIDispatch()

	defer result.Release()

	// Get query results
	countVar, err := oleutil.GetProperty(result, "Count")
	if err != nil {
		fmt.Println("Error getting result count:", err)
		return
	}
	count := int(countVar.Val)

	for i := 0; i < count; i++ {
		itemRaw, err := oleutil.CallMethod(result, "ItemIndex", i)
		if err != nil {
			fmt.Println("Error getting result item:", err)
			return
		}
		item := itemRaw.ToIDispatch()
		defer item.Release()

		// Get the value of "displayName" property
		displayNameVar, err := oleutil.GetProperty(item, "displayName")
		if err != nil {
			fmt.Println("Error getting displayName property:", err)
			return
		}
		displayName := displayNameVar.ToString()
		fmt.Println("displayName: ", displayName)

		instanceGuidVar, err := oleutil.GetProperty(item, "instanceGuid")
		if err != nil {
			fmt.Println("Error getting instanceGuid property:", err)
			return
		}
		instanceGuid := instanceGuidVar.ToString()
		fmt.Println("instanceGuid: ", instanceGuid)

		productStateVar, err := oleutil.GetProperty(item, "productState")
		if err != nil {
			fmt.Println("Error getting productState property:", err)
			return
		}

		fmt.Println("productState: ", productStateVar.Val)

		pathToSignedProductExeVar, err := oleutil.GetProperty(item, "pathToSignedProductExe")
		if err != nil {
			fmt.Println("Error getting pathToSignedProductExe property:", err)
			return
		}

		fmt.Println("pathToSignedProductExe: ", pathToSignedProductExeVar.ToString())

	}
}
