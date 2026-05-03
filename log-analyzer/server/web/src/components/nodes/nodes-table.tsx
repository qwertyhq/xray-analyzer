'use client'

import { useRef, useEffect, useState } from 'react'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Button } from '@/components/ui/button'
import { Trash2 } from 'lucide-react'
import { useTranslations } from 'next-intl'
import { isValidDate, formatRelativeTime } from '@/lib/utils/date'
import { NodeStats } from '@/lib/types'

interface NodesTableProps {
  nodes: NodeStats[]
  onDeleteNode?: (nodeId: string) => void
  onDelete?: (nodeId: string) => void
  showActions?: boolean
}

// Store previous values for change tracking
interface PrevNodeState {
  is_connected: boolean
  blacklist_hits: number
  online_users: number
}

export function NodesTable({ nodes, onDeleteNode, onDelete, showActions }: NodesTableProps) {
  const t = useTranslations('nodesTable')
  // Support both variants: onDeleteNode and onDelete
  const handleDelete = onDeleteNode || onDelete
  const showDeleteButton = showActions || !!handleDelete
  
  const prevNodesRef = useRef<Map<string, PrevNodeState>>(new Map())
  const [changedNodes, setChangedNodes] = useState<Map<string, {
    statusChanged: boolean
    blacklistIncreased: boolean
    onlineChanged: boolean
  }>>(new Map())

  useEffect(() => {
    const newChanges = new Map<string, {
      statusChanged: boolean
      blacklistIncreased: boolean
      onlineChanged: boolean
    }>()

    nodes.forEach(node => {
      const prev = prevNodesRef.current.get(node.node_id)
      
      if (prev) {
        const statusChanged = prev.is_connected !== node.is_connected
        const blacklistIncreased = node.blacklist_hits > prev.blacklist_hits
        const onlineChanged = prev.online_users !== node.online_users

        if (statusChanged || blacklistIncreased || onlineChanged) {
          newChanges.set(node.node_id, {
            statusChanged,
            blacklistIncreased,
            onlineChanged
          })
        }
      }
    })

    if (newChanges.size > 0) {
      setChangedNodes(newChanges)
      
      // Remove animation after 2 seconds
      const timer = setTimeout(() => {
        setChangedNodes(new Map())
      }, 2000)

      return () => clearTimeout(timer)
    }

    // Save current state
    const newPrevMap = new Map<string, PrevNodeState>()
    nodes.forEach(node => {
      newPrevMap.set(node.node_id, {
        is_connected: node.is_connected,
        blacklist_hits: node.blacklist_hits,
        online_users: node.online_users
      })
    })
    prevNodesRef.current = newPrevMap
  }, [nodes])

  // Update prevNodesRef after each render
  useEffect(() => {
    const newPrevMap = new Map<string, PrevNodeState>()
    nodes.forEach(node => {
      newPrevMap.set(node.node_id, {
        is_connected: node.is_connected,
        blacklist_hits: node.blacklist_hits,
        online_users: node.online_users
      })
    })
    prevNodesRef.current = newPrevMap
  }, [nodes])

  return (
    <div className="rounded-md border overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="whitespace-nowrap">{t('nodeId')}</TableHead>
            <TableHead className="whitespace-nowrap">{t('status')}</TableHead>
            <TableHead className="text-right whitespace-nowrap hidden sm:table-cell">{t('requests')}</TableHead>
            <TableHead className="text-right whitespace-nowrap">{t('blacklist')}</TableHead>
            <TableHead className="text-right whitespace-nowrap">{t('online')}</TableHead>
            <TableHead className="text-right whitespace-nowrap hidden md:table-cell">{t('totalUsers')}</TableHead>
            <TableHead className="whitespace-nowrap hidden lg:table-cell">{t('lastSeen')}</TableHead>
            {showDeleteButton && <TableHead className="w-[50px]"></TableHead>}
          </TableRow>
        </TableHeader>
        <TableBody>
          {nodes.map((node) => {
            const changes = changedNodes.get(node.node_id)
            
            return (
              <TableRow 
                key={node.node_id}
              >
                <TableCell className="font-medium whitespace-nowrap">{node.node_id}</TableCell>
                <TableCell>
                  <Badge
                    variant={node.is_connected ? 'default' : 'secondary'}
                    className={`transition-all duration-300 ${
                      changes?.statusChanged 
                        ? node.is_connected 
                          ? 'ring-2 ring-green-500 ring-offset-1' 
                          : 'ring-2 ring-red-500 ring-offset-1'
                        : ''
                    }`}
                  >
                    {node.is_connected ? t('statusOnline') : t('statusOffline')}
                  </Badge>
                </TableCell>
                <TableCell className="text-right hidden sm:table-cell">{node.total_requests.toLocaleString()}</TableCell>
                <TableCell className={`text-right transition-colors duration-300 ${
                  changes?.blacklistIncreased ? 'text-red-500 font-bold' : ''
                }`}>
                  {node.blacklist_hits.toLocaleString()}
                </TableCell>
                <TableCell className={`text-right transition-colors duration-300 ${
                  changes?.onlineChanged ? 'text-blue-500 font-bold' : ''
                }`}>
                  {node.online_users.toLocaleString()}
                </TableCell>
                <TableCell className="text-right hidden md:table-cell">{node.unique_users.toLocaleString()}</TableCell>
                <TableCell className="text-muted-foreground hidden lg:table-cell">
                  {isValidDate(node.last_seen) ? formatRelativeTime(node.last_seen) : t('never')}
                </TableCell>
                {showDeleteButton && handleDelete && (
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => handleDelete(node.node_id)}
                      className="h-8 w-8 text-muted-foreground hover:text-destructive"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                )}
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
    </div>
  )
}
