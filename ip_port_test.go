package main

import (
	"reflect"
	"testing"
)

func TestGenerateIPsFromCIDR(t *testing.T) {
	type args struct {
		cidr string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name:    "10.10.0.0/24",
			args:    args{"10.10.0.0/24"},
			want:    []string{"10.10.0.1", "10.10.0.2", "10.10.0.3", "10.10.0.4", "10.10.0.5", "10.10.0.6", "10.10.0.7", "10.10.0.8", "10.10.0.9", "10.10.0.10", "10.10.0.11", "10.10.0.12", "10.10.0.13", "10.10.0.14", "10.10.0.15", "10.10.0.16", "10.10.0.17", "10.10.0.18", "10.10.0.19", "10.10.0.20", "10.10.0.21", "10.10.0.22", "10.10.0.23", "10.10.0.24", "10.10.0.25", "10.10.0.26", "10.10.0.27", "10.10.0.28", "10.10.0.29", "10.10.0.30", "10.10.0.31", "10.10.0.32", "10.10.0.33", "10.10.0.34", "10.10.0.35", "10.10.0.36", "10.10.0.37", "10.10.0.38", "10.10.0.39", "10.10.0.40", "10.10.0.41", "10.10.0.42", "10.10.0.43", "10.10.0.44", "10.10.0.45", "10.10.0.46", "10.10.0.47", "10.10.0.48", "10.10.0.49", "10.10.0.50", "10.10.0.51", "10.10.0.52", "10.10.0.53", "10.10.0.54", "10.10.0.55", "10.10.0.56", "10.10.0.57", "10.10.0.58", "10.10.0.59", "10.10.0.60", "10.10.0.61", "10.10.0.62", "10.10.0.63", "10.10.0.64", "10.10.0.65", "10.10.0.66", "10.10.0.67", "10.10.0.68", "10.10.0.69", "10.10.0.70", "10.10.0.71", "10.10.0.72", "10.10.0.73", "10.10.0.74", "10.10.0.75", "10.10.0.76", "10.10.0.77", "10.10.0.78", "10.10.0.79", "10.10.0.80", "10.10.0.81", "10.10.0.82", "10.10.0.83", "10.10.0.84", "10.10.0.85", "10.10.0.86", "10.10.0.87", "10.10.0.88", "10.10.0.89", "10.10.0.90", "10.10.0.91", "10.10.0.92", "10.10.0.93", "10.10.0.94", "10.10.0.95", "10.10.0.96", "10.10.0.97", "10.10.0.98", "10.10.0.99", "10.10.0.100", "10.10.0.101", "10.10.0.102", "10.10.0.103", "10.10.0.104", "10.10.0.105", "10.10.0.106", "10.10.0.107", "10.10.0.108", "10.10.0.109", "10.10.0.110", "10.10.0.111", "10.10.0.112", "10.10.0.113", "10.10.0.114", "10.10.0.115", "10.10.0.116", "10.10.0.117", "10.10.0.118", "10.10.0.119", "10.10.0.120", "10.10.0.121", "10.10.0.122", "10.10.0.123", "10.10.0.124", "10.10.0.125", "10.10.0.126", "10.10.0.127", "10.10.0.128", "10.10.0.129", "10.10.0.130", "10.10.0.131", "10.10.0.132", "10.10.0.133", "10.10.0.134", "10.10.0.135", "10.10.0.136", "10.10.0.137", "10.10.0.138", "10.10.0.139", "10.10.0.140", "10.10.0.141", "10.10.0.142", "10.10.0.143", "10.10.0.144", "10.10.0.145", "10.10.0.146", "10.10.0.147", "10.10.0.148", "10.10.0.149", "10.10.0.150", "10.10.0.151", "10.10.0.152", "10.10.0.153", "10.10.0.154", "10.10.0.155", "10.10.0.156", "10.10.0.157", "10.10.0.158", "10.10.0.159", "10.10.0.160", "10.10.0.161", "10.10.0.162", "10.10.0.163", "10.10.0.164", "10.10.0.165", "10.10.0.166", "10.10.0.167", "10.10.0.168", "10.10.0.169", "10.10.0.170", "10.10.0.171", "10.10.0.172", "10.10.0.173", "10.10.0.174", "10.10.0.175", "10.10.0.176", "10.10.0.177", "10.10.0.178", "10.10.0.179", "10.10.0.180", "10.10.0.181", "10.10.0.182", "10.10.0.183", "10.10.0.184", "10.10.0.185", "10.10.0.186", "10.10.0.187", "10.10.0.188", "10.10.0.189", "10.10.0.190", "10.10.0.191", "10.10.0.192", "10.10.0.193", "10.10.0.194", "10.10.0.195", "10.10.0.196", "10.10.0.197", "10.10.0.198", "10.10.0.199", "10.10.0.200", "10.10.0.201", "10.10.0.202", "10.10.0.203", "10.10.0.204", "10.10.0.205", "10.10.0.206", "10.10.0.207", "10.10.0.208", "10.10.0.209", "10.10.0.210", "10.10.0.211", "10.10.0.212", "10.10.0.213", "10.10.0.214", "10.10.0.215", "10.10.0.216", "10.10.0.217", "10.10.0.218", "10.10.0.219", "10.10.0.220", "10.10.0.221", "10.10.0.222", "10.10.0.223", "10.10.0.224", "10.10.0.225", "10.10.0.226", "10.10.0.227", "10.10.0.228", "10.10.0.229", "10.10.0.230", "10.10.0.231", "10.10.0.232", "10.10.0.233", "10.10.0.234", "10.10.0.235", "10.10.0.236", "10.10.0.237", "10.10.0.238", "10.10.0.239", "10.10.0.240", "10.10.0.241", "10.10.0.242", "10.10.0.243", "10.10.0.244", "10.10.0.245", "10.10.0.246", "10.10.0.247", "10.10.0.248", "10.10.0.249", "10.10.0.250", "10.10.0.251", "10.10.0.252", "10.10.0.253", "10.10.0.254"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateIPsFromCIDR(tt.args.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateIPsFromCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateIPsFromCIDR() got = %v, want %v", got, tt.want)
			}
		})
	}
}
