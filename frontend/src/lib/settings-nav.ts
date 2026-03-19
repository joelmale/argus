import {
  ActivitySquare,
  Bell,
  Brain,
  Database,
  History,
  KeyRound,
  LibraryBig,
  PlugZap,
  ScanLine,
  Shield,
  Trash2,
  UserPlus,
  Wifi,
} from "lucide-react";

export const SETTINGS_SECTIONS = [
  {
    heading: "Discovery Engine",
    items: [
      { id: "scan-configuration", label: "Scan Configuration", icon: ScanLine },
      { id: "ai-agent", label: "AI Agent", icon: Brain },
      { id: "network-snmp", label: "Network & SNMP", icon: Wifi },
      { id: "fingerprint-datasets", label: "Fingerprint Datasets", icon: LibraryBig },
    ],
  },
  {
    heading: "Automation",
    items: [
      { id: "notifications", label: "Notifications", icon: Bell },
      { id: "integrations", label: "Integrations", icon: PlugZap },
      { id: "reports-metrics", label: "Reports & Metrics", icon: ActivitySquare },
      { id: "data-retention", label: "Data Retention", icon: Database },
    ],
  },
  {
    heading: "Access & Control",
    items: [
      { id: "user-management", label: "User Management", icon: UserPlus },
      { id: "api-keys", label: "API Keys", icon: KeyRound },
      { id: "audit-activity", label: "Audit Activity", icon: History },
      { id: "plugins-drivers", label: "Plugins & Drivers", icon: Shield },
      { id: "danger-zone", label: "Danger Zone", icon: Trash2 },
    ],
  },
] as const;
