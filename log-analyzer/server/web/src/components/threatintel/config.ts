import { Bug, Crosshair, Fish, Bot, Skull, Activity, Heart, Dice1, Users, Newspaper, Download, Globe, AlertTriangle, Megaphone, Coins, Pill, ShieldAlert, Anchor, BadgeAlert, ExternalLink, Video, Eye } from "lucide-react";
import { ThreatType, ThreatSource } from "@/lib/types";
import React from "react";

export const threatTypeConfig: Record<ThreatType, { icon: React.ReactNode; color: string; label: string }> = {
  malware: { icon: React.createElement(Bug, { className: "h-4 w-4" }), color: "bg-red-500", label: "Malware" },
  c2: { icon: React.createElement(Crosshair, { className: "h-4 w-4" }), color: "bg-purple-500", label: "C2 Server" },
  phishing: { icon: React.createElement(Fish, { className: "h-4 w-4" }), color: "bg-orange-500", label: "Phishing" },
  botnet: { icon: React.createElement(Bot, { className: "h-4 w-4" }), color: "bg-pink-500", label: "Botnet" },
  ransomware: { icon: React.createElement(Skull, { className: "h-4 w-4" }), color: "bg-red-700", label: "Ransomware" },
  adware: { icon: React.createElement(Activity, { className: "h-4 w-4" }), color: "bg-yellow-500", label: "Adware" },
  tracker: { icon: React.createElement(Activity, { className: "h-4 w-4" }), color: "bg-gray-500", label: "Tracker" },
  // Content categories
  porn: { icon: React.createElement(Heart, { className: "h-4 w-4" }), color: "bg-pink-600", label: "porn" },
  gambling: { icon: React.createElement(Dice1, { className: "h-4 w-4" }), color: "bg-emerald-600", label: "gambling" },
  social: { icon: React.createElement(Users, { className: "h-4 w-4" }), color: "bg-blue-500", label: "social" },
  fakenews: { icon: React.createElement(Newspaper, { className: "h-4 w-4" }), color: "bg-amber-600", label: "fakenews" },
  // P2P
  torrent: { icon: React.createElement(Download, { className: "h-4 w-4" }), color: "bg-cyan-600", label: "torrent" },
  // Anonymization
  tor: { icon: React.createElement(Globe, { className: "h-4 w-4" }), color: "bg-violet-600", label: "tor" },
  // BlockList Project categories
  abuse: { icon: React.createElement(AlertTriangle, { className: "h-4 w-4" }), color: "bg-orange-600", label: "abuse" },
  ads: { icon: React.createElement(Megaphone, { className: "h-4 w-4" }), color: "bg-yellow-600", label: "ads" },
  crypto: { icon: React.createElement(Coins, { className: "h-4 w-4" }), color: "bg-amber-500", label: "crypto" },
  drugs: { icon: React.createElement(Pill, { className: "h-4 w-4" }), color: "bg-lime-600", label: "drugs" },
  fraud: { icon: React.createElement(ShieldAlert, { className: "h-4 w-4" }), color: "bg-red-600", label: "fraud" },
  piracy: { icon: React.createElement(Anchor, { className: "h-4 w-4" }), color: "bg-slate-600", label: "piracy" },
  scam: { icon: React.createElement(BadgeAlert, { className: "h-4 w-4" }), color: "bg-rose-600", label: "scam" },
  redirect: { icon: React.createElement(ExternalLink, { className: "h-4 w-4" }), color: "bg-gray-600", label: "redirect" },
  tiktok: { icon: React.createElement(Video, { className: "h-4 w-4" }), color: "bg-black", label: "tiktok" },
  tracking: { icon: React.createElement(Eye, { className: "h-4 w-4" }), color: "bg-indigo-500", label: "tracking" },
};

export const sourceLabels: Record<ThreatSource, string> = {
  urlhaus: "URLhaus",
  feodo: "Feodo Tracker",
  threatfox: "ThreatFox",
  sslbl: "SSL Blacklist",
  stevenblack: "StevenBlack",
  // Content category blocklists
  "porn-blocklist": "Porn Blocklist",
  "gambling-blocklist": "Gambling Blocklist",
  "social-blocklist": "Social Blocklist",
  "fakenews-blocklist": "FakeNews Blocklist",
  // P2P
  "torrent-trackers": "Torrent Trackers",
  // Anonymization
  "tor-exit-nodes": "Tor Exit Nodes",
  // BlockList Project sources
  "blocklist-abuse": "BlockList: Abuse",
  "blocklist-ads": "BlockList: Ads",
  "blocklist-crypto": "BlockList: Crypto",
  "blocklist-drugs": "BlockList: Drugs",
  "blocklist-fraud": "BlockList: Fraud",
  "blocklist-malware": "BlockList: Malware",
  "blocklist-phishing": "BlockList: Phishing",
  "blocklist-piracy": "BlockList: Piracy",
  "blocklist-porn": "BlockList: Porn",
  "blocklist-scam": "BlockList: Scam",
  "blocklist-redirect": "BlockList: Redirect",
  "blocklist-tiktok": "BlockList: TikTok",
  "blocklist-torrent": "BlockList: Torrent",
  "blocklist-tracking": "BlockList: Tracking",
  "blocklist-ransomware": "BlockList: Ransomware",
};
