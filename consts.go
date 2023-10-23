package main

import (
	"encoding/base64"
	"time"
)

const (
	WarpPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
)

var (
	connTimeout = time.Millisecond * 1500

	warpPorts = []int{
		500, 854, 859, 864, 878, 880, 890, 891, 894, 903,
		908, 928, 934, 939, 942, 943, 945, 946, 955, 968,
		987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387,
		1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177,
		4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
	}

	warpCIDRs = []string{
		"162.159.192.0/24",
		"162.159.193.0/24",
		"162.159.195.0/24",
		"162.159.204.0/24",
		"188.114.96.0/24",
		"188.114.97.0/24",
		"188.114.98.0/24",
		"188.114.99.0/24",
	}

	warpHandshakePacket, _ = base64.StdEncoding.DecodeString("AQAAAJkjn0LiAOmbiXL4oI5vnx4ezexwwLX9RbNCOzJ3V/+lacQqfABbwsPywsCAVvOdiq7gnJ6BT/609UrCyPE1mFZ0OfXOPhgUERpoyjB/Zc21Ql+n5JVxLPh6DeHXQwnf10rm0x4ezo66p0T7vUbhU5WOHjW6QxJ84Lzg/eMmr6NxAAAAAAAAAAAAAAAAAAAAAA==")
)
