"use client";

import { useState } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  Smartphone,
  ChevronDown,
  ChevronRight,
  Phone,
  User,
  Trash2,
  Loader2,
} from "lucide-react";
import { RemnawaveAbuseUser } from "@/lib/types";

// Platform icons
function getPlatformIcon(platform: string) {
  const p = platform?.toLowerCase() || "";
  if (p.includes("ios") || p.includes("iphone") || p.includes("ipad")) {
    return "🍎";
  }
  if (p.includes("android")) {
    return "🤖";
  }
  if (p.includes("windows")) {
    return "🪟";
  }
  if (p.includes("mac") || p.includes("macos")) {
    return "🍎";
  }
  if (p.includes("linux")) {
    return "🐧";
  }
  return "📱";
}

interface RemnawaveAbuseTableProps {
  users: RemnawaveAbuseUser[];
  onHwidCleared?: (userUuid: string) => void;
}

export function RemnawaveAbuseTable({ users, onHwidCleared }: RemnawaveAbuseTableProps) {
  const [expandedUsers, setExpandedUsers] = useState<Set<string>>(new Set());
  const [clearingHwid, setClearingHwid] = useState<string | null>(null);

  const toggleUser = (uuid: string) => {
    setExpandedUsers((prev) => {
      const next = new Set(prev);
      if (next.has(uuid)) {
        next.delete(uuid);
      } else {
        next.add(uuid);
      }
      return next;
    });
  };

  const handleClearHwid = async (userUuid: string) => {
    setClearingHwid(userUuid);
    try {
      const response = await fetch("/api/remnawave/hwid-clear", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userUuid }),
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(error || "Failed to clear HWID");
      }

      onHwidCleared?.(userUuid);
    } catch (error) {
      console.error("Failed to clear HWID:", error);
      alert(`Ошибка: ${error instanceof Error ? error.message : "Не удалось очистить HWID"}`);
    } finally {
      setClearingHwid(null);
    }
  };

  if (users.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <Smartphone className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p className="text-lg font-medium">Подозрительных не найдено</p>
        <p className="text-sm">Все пользователи в рамках лимитов устройств</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-8"></TableHead>
            <TableHead>Пользователь</TableHead>
            <TableHead>Статус</TableHead>
            <TableHead className="text-right">Устройства</TableHead>
            <TableHead className="text-right">Превышение</TableHead>
            <TableHead>Платформы</TableHead>
            <TableHead>Риск</TableHead>
            <TableHead className="w-24">Действия</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {users.map((user) => {
            const isExpanded = expandedUsers.has(user.uuid);
            const riskLevel = user.excessDevices >= 3 ? "high" : user.excessDevices === 2 ? "medium" : "low";
            
            return (
              <Collapsible key={user.uuid} asChild open={isExpanded}>
                <>
                  <CollapsibleTrigger asChild>
                    <TableRow
                      className="cursor-pointer hover:bg-muted/50"
                      onClick={() => toggleUser(user.uuid)}
                    >
                      <TableCell>
                        {isExpanded ? (
                          <ChevronDown className="h-4 w-4" />
                        ) : (
                          <ChevronRight className="h-4 w-4" />
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="space-y-1">
                          <div className="font-medium">{user.username}</div>
                          {user.email && (
                            <div className="text-xs text-muted-foreground">
                              {user.email}
                            </div>
                          )}
                          {user.parsedNote?.real_name && (
                            <div className="text-xs flex items-center gap-1">
                              <User className="h-3 w-3" />
                              {user.parsedNote.real_name}
                            </div>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            user.status === "ACTIVE" ? "default" : "secondary"
                          }
                          className={user.status === "ACTIVE" ? "bg-green-500" : ""}
                        >
                          {user.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <span className="text-destructive font-bold">
                          {user.deviceCount}
                        </span>
                        <span className="text-muted-foreground">
                          /{user.deviceLimit}
                        </span>
                      </TableCell>
                      <TableCell className="text-right">
                        <Badge variant="destructive">
                          +{user.excessDevices}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1 flex-wrap">
                          {user.platforms.map((p, i) => (
                            <span key={i} title={p}>
                              {getPlatformIcon(p)}
                            </span>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={riskLevel === "high" ? "destructive" : riskLevel === "medium" ? "default" : "secondary"}
                          className={riskLevel === "medium" ? "bg-orange-500" : ""}
                        >
                          {riskLevel === "high" ? "Высокий" : riskLevel === "medium" ? "Средний" : "Низкий"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-destructive hover:text-destructive hover:bg-destructive/10"
                              onClick={(e) => e.stopPropagation()}
                              disabled={clearingHwid === user.uuid}
                            >
                              {clearingHwid === user.uuid ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                              ) : (
                                <Trash2 className="h-4 w-4" />
                              )}
                              <span className="ml-1.5 hidden sm:inline">Clear</span>
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent onClick={(e) => e.stopPropagation()}>
                            <AlertDialogHeader>
                              <AlertDialogTitle>Очистить HWID устройства?</AlertDialogTitle>
                              <AlertDialogDescription>
                                Будут удалены все {user.deviceCount} устройств пользователя{" "}
                                <span className="font-medium text-foreground">{user.username}</span>.
                                Пользователю придётся заново подключить устройства.
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Отмена</AlertDialogCancel>
                              <AlertDialogAction
                                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                onClick={() => handleClearHwid(user.uuid)}
                              >
                                Очистить HWID
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      </TableCell>
                    </TableRow>
                  </CollapsibleTrigger>
                  <CollapsibleContent asChild>
                    <TableRow className="bg-muted/30 hover:bg-muted/30">
                      <TableCell colSpan={8} className="p-0">
                        <div className="p-4 space-y-4">
                          {/* Contact Info */}
                          {(user.parsedNote?.phone || user.parsedNote?.telegram_user) && (
                            <div className="flex gap-4 text-sm">
                              {user.parsedNote?.phone && (
                                <div className="flex items-center gap-1">
                                  <Phone className="h-4 w-4 text-muted-foreground" />
                                  {user.parsedNote.phone}
                                </div>
                              )}
                              {user.parsedNote?.telegram_user && (
                                <div className="flex items-center gap-1">
                                  <span className="text-muted-foreground">@</span>
                                  {user.parsedNote.telegram_user}
                                </div>
                              )}
                            </div>
                          )}

                          {/* Devices */}
                          <div>
                            <div className="text-sm font-medium mb-2 flex items-center gap-2">
                              <Smartphone className="h-4 w-4" />
                              Устройства ({user.devices.length})
                            </div>
                            <div className="grid gap-2">
                              {user.devices.map((device) => (
                                <div 
                                  key={device.hwid} 
                                  className="text-xs bg-background p-3 rounded border grid grid-cols-2 md:grid-cols-4 gap-2"
                                >
                                  <div>
                                    <span className="text-muted-foreground">HWID:</span>
                                    <span className="ml-1 font-mono">{device.hwid.slice(0, 16)}...</span>
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground">Platform:</span>
                                    <span className="ml-1">{getPlatformIcon(device.platform || "")} {device.platform || "Unknown"}</span>
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground">Model:</span>
                                    <span className="ml-1">{device.deviceModel || "—"}</span>
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground">OS:</span>
                                    <span className="ml-1">{device.osVersion || "—"}</span>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* Last Activity */}
                          {user.lastActivity && (
                            <div className="text-xs text-muted-foreground">
                              Последняя активность: {new Date(user.lastActivity).toLocaleString()}
                            </div>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  </CollapsibleContent>
                </>
              </Collapsible>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
