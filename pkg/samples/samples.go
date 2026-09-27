package samples

// SampleConfig represents a pre-loaded configuration for evaluation
type SampleConfig struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Vendor      string `json:"vendor"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Content     string `json:"content"`
}

// GetSampleConfigs returns realistic multi-vendor configurations
func GetSampleConfigs() []SampleConfig {
	return []SampleConfig{
		{
			ID:          "cisco-ios-xe",
			Name:        "Cisco Catalyst 9300 (IOS-XE 17.9)",
			Vendor:      "Cisco",
			Category:    "Enterprise Core Switch",
			Description: "Misconfigured corporate switch with active Telnet, unencrypted HTTP, and missing remote syslog.",
			Content: `!
version 17.9.4a
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname core-switch-mumbai-01
!
ip domain name internal.defense.in
ip ssh version 1
!
username secadmin privilege 15 secret 5 $1$mERr$9.1jX1L3Fm9Qz
!
interface GigabitEthernet1/0/1
 description UPLINK-TO-BORDER-ROUTER
 switchport mode trunk
!
interface Vlan10
 description USERS-VLAN
 ip address 10.10.10.1 255.255.255.0
 no shutdown
!
ip http server
no ip http secure-server
!
line con 0
 exec-timeout 0 0
 stopbits 2
line vty 0 4
 transport input telnet ssh
 exec-timeout 0 0
 login local
!
end`,
		},
		{
			ID:          "juniper-junos",
			Name:        "Juniper SRX345 Next-Gen Firewall",
			Vendor:      "Juniper",
			Category:    "Border Firewall",
			Description: "Branch security gateway with legacy web-management and missing session inactivity limits.",
			Content: `version 21.4R3-S5;
system {
    host-name border-fw-delhi-01;
    domain-name perimeter.gov.in;
    services {
        ssh {
            protocol-version v2;
        }
        telnet;
        web-management {
            http {
                interface ge-0/0/0.0;
            }
        }
    }
    syslog {
        archive size 100k files 3;
        user * {
            any emergency;
        }
    }
    ntp {
        server 10.10.1.50;
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 192.168.1.1/24;
            }
        }
    }
}`,
		},
		{
			ID:          "sonic-whitebox",
			Name:        "SONiC Linux (White-Box Open Switch)",
			Vendor:      "Open Networking (White-Box)",
			Category:    "Hyperscale AI / Leaf Fabric",
			Description: "Disaggregated open-source switch containing novel, custom syntax lines for Laya AI training.",
			Content: `{
  "DEVICE_METADATA": {
    "localhost": {
      "hostname": "leaf-sonic-fabric-04",
      "hwsku": "Dell-EMC-S5248F-ON",
      "type": "LeafRouter",
      "platform": "x86_64-dell_s5248f_c3538-r0",
      "mac": "50:00:00:ab:cd:ef"
    }
  },
  "FEATURE": {
    "telemetry": {
      "status": "enabled"
    },
    "ssh": {
      "status": "enabled"
    }
  },
  "MGMT_INTERFACE": {
    "eth0": {
      "mgmt_ip": "10.250.0.14/24",
      "gwaddr": "10.250.0.1"
    }
  },
  "CUSTOM_ADMIN_POLICY": {
    "idle-timeout 10": "enforced",
    "admin-telnet disable": "true",
    "remote-syslog host 10.50.100.1": "active",
    "custom-access line vty exec-timeout 10": "configured"
  }
}`,
		},
		{
			ID:          "paloalto-panos",
			Name:        "Palo Alto PA-3260 (PAN-OS 10.2)",
			Vendor:      "Palo Alto Networks",
			Category:    "Data Center Perimeter Firewall",
			Description: "High-throughput firewall with Telnet disabled but weak permitted IP management access.",
			Content: `set deviceconfig system hostname dc-panw-fw-01
set deviceconfig system domain internal.defense.in
set deviceconfig system ip-address 10.10.100.2 netmask 255.255.255.0
set deviceconfig system default-gateway 10.10.100.1
set deviceconfig system service disable-telnet yes
set deviceconfig system service disable-http yes
set deviceconfig system permitted-ip 0.0.0.0/0
set deviceconfig system update-server updates.paloaltonetworks.com
set deviceconfig system ntp-servers primary-ntp-server 10.10.1.1`,
		},
		{
			ID:          "fortinet-fortios",
			Name:        "Fortinet FortiGate 100F (FortiOS 7.2)",
			Vendor:      "Fortinet",
			Category:    "Enterprise Edge Firewall",
			Description: "Edge security appliance with admin Telnet active and default administrator timeout.",
			Content: `config system global
    set hostname "edge-fortigate-blr-01"
    set admin-sport 8443
    set admin-ssh-port 22
    set admin-telnet enable
    set admintimeout 480
    set timezone 55
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set vdom "root"
    next
end
config log syslogd setting
    set status disable
end`,
		},
	}
}
