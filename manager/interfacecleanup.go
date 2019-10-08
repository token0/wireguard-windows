/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"log"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/tun/wintun"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/services"
)

func cleanupStaleWintunInterfaces() {
	defer printPanic()

	m, err := mgr.Connect()
	if err != nil {
		return
	}
	defer m.Disconnect()

	var existingLowerConfigs map[string]bool
	existingConfigs, err := conf.ListConfigNames()
	if err != nil {
		log.Printf("Skipping Wintun interface cleanup because listing configurations failed: %v", err)
	} else {
		existingLowerConfigs = make(map[string]bool, len(existingConfigs))
		for _, config := range existingConfigs {
			existingLowerConfigs[strings.ToLower(config)] = true
		}
	}

	tun.WintunPool.DeleteMatchingInterfaces(func(wt *wintun.Interface) bool {
		interfaceName, err := wt.Name()
		if err != nil {
			log.Printf("Removing Wintun interface %s because determining interface name failed: %v", wt.GUID().String(), err)
			return true
		}
		_, err = services.ServiceNameOfTunnel(interfaceName)
		if err != nil {
			log.Printf("Removing Wintun interface ‘%s’ because determining tunnel service name failed: %v", interfaceName, err)
			return true
		}
		if existingLowerConfigs == nil || existingLowerConfigs[strings.ToLower(interfaceName)] {
			return false
		}
		log.Printf("Removing Wintun interface ‘%s’ because no configuration for it exists", interfaceName)
		return true
	})

	tun.WintunPool.EnableMatchingInterfaces(func(wt *wintun.Interface) wintun.EnableMatchingInterfacesAction {
		interfaceName, err := wt.Name()
		if err != nil {
			log.Printf("Skipping Wintun interface %s because determining interface name failed: %v", wt.GUID().String(), err)
			return wintun.SkipInterface
		}
		serviceName, err := services.ServiceNameOfTunnel(interfaceName)
		if err != nil {
			log.Printf("Skipping Wintun interface ‘%s’ because determining tunnel service name failed: %v", interfaceName, err)
			return wintun.SkipInterface
		}
		service, err := m.OpenService(serviceName)
		if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			log.Printf("Disabling Wintun interface ‘%s’ because no service for it exists", interfaceName)
			return wintun.DisableInterface
		} else if err != nil {
			return wintun.SkipInterface
		}
		defer service.Close()
		status, err := service.Query()
		if err != nil {
			return wintun.SkipInterface
		}
		if status.State == svc.Stopped {
			log.Printf("Disabling Wintun interface ‘%s’ because its service is stopped", interfaceName)
			return wintun.DisableInterface
		}
		return wintun.SkipInterface
	})
}
