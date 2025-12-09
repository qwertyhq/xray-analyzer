"use client";

import {
  useState,
  useRef,
  useEffect,
  useCallback,
  type MouseEvent as ReactMouseEvent,
} from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Textarea } from "@/components/ui/textarea";
import {
  Bot,
  Send,
  Loader2,
  User,
  Sparkles,
  X,
  Maximize2,
  Minimize2,
  MessageSquare,
  Trash2,
  Plus,
  History,
  ChevronLeft,
} from "lucide-react";
import ReactMarkdown from "react-markdown";
import { cn } from "@/lib/utils";

interface Message {
  id?: number;
  role: "user" | "assistant";
  content: string;
  tokensUsed?: number;
}

interface ChatSession {
  id: string;
  title: string;
  created_at: string;
  updated_at: string;
  total_tokens: number;
}

type ChatView = "chat" | "history";

export function FloatingAIChat() {
  const [isOpen, setIsOpen] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [view, setView] = useState<ChatView>("chat");
  const [messages, setMessages] = useState<Message[]>([]);
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [streaming, setStreaming] = useState(false);
  const [streamContent, setStreamContent] = useState("");

  // Resize state
  const [size, setSize] = useState({ width: 420, height: 550 });
  const [isResizing, setIsResizing] = useState(false);
  const resizeRef = useRef<{ startX: number; startY: number; startW: number; startH: number } | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, streamContent]);

  // Focus input when opened
  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen]);

  // Load sessions
  const loadSessions = useCallback(async () => {
    try {
      const token = localStorage.getItem("auth_token");
      const headers: HeadersInit = {};
      if (token) headers["Authorization"] = `Bearer ${token}`;

      const res = await fetch("/api/ai/sessions", { headers });
      const data = await res.json();
      if (Array.isArray(data)) {
        setSessions(data);
      }
    } catch (err) {
      console.error("Failed to load sessions:", err);
    }
  }, []);

  // Load session messages
  const loadSession = useCallback(async (sessionId: string) => {
    try {
      const token = localStorage.getItem("auth_token");
      const headers: HeadersInit = {};
      if (token) headers["Authorization"] = `Bearer ${token}`;

      const res = await fetch(`/api/ai/sessions/${sessionId}`, { headers });
      const data = await res.json();
      if (data.messages) {
        setMessages(
          data.messages.map((m: Message) => ({
            ...m,
            role: m.role as "user" | "assistant",
          }))
        );
      }
      setCurrentSessionId(sessionId);
      setView("chat");
    } catch (err) {
      console.error("Failed to load session:", err);
    }
  }, []);

  // Create new session
  const createSession = useCallback(async () => {
    try {
      const token = localStorage.getItem("auth_token");
      const headers: HeadersInit = { "Content-Type": "application/json" };
      if (token) headers["Authorization"] = `Bearer ${token}`;

      const res = await fetch("/api/ai/sessions", {
        method: "POST",
        headers,
        body: JSON.stringify({ title: "Новый чат" }),
      });
      const session = await res.json();
      if (session.id) {
        setCurrentSessionId(session.id);
        setMessages([]);
        loadSessions();
        return session.id;
      }
    } catch (err) {
      console.error("Failed to create session:", err);
    }
    return null;
  }, [loadSessions]);

  // Delete session
  const deleteSession = useCallback(
    async (sessionId: string) => {
      try {
        const token = localStorage.getItem("auth_token");
        const headers: HeadersInit = {};
        if (token) headers["Authorization"] = `Bearer ${token}`;

        await fetch(`/api/ai/sessions/${sessionId}`, {
          method: "DELETE",
          headers,
        });

        if (currentSessionId === sessionId) {
          setCurrentSessionId(null);
          setMessages([]);
        }
        loadSessions();
      } catch (err) {
        console.error("Failed to delete session:", err);
      }
    },
    [currentSessionId, loadSessions]
  );

  // Clear all sessions
  const clearAllSessions = useCallback(async () => {
    try {
      const token = localStorage.getItem("auth_token");
      const headers: HeadersInit = {};
      if (token) headers["Authorization"] = `Bearer ${token}`;

      await fetch("/api/ai/sessions", {
        method: "DELETE",
        headers,
      });

      setCurrentSessionId(null);
      setMessages([]);
      setSessions([]);
    } catch (err) {
      console.error("Failed to clear sessions:", err);
    }
  }, []);

  // Load sessions when opened
  useEffect(() => {
    if (isOpen) {
      loadSessions();
    }
  }, [isOpen, loadSessions]);

  // Auto-load last session when opening chat
  useEffect(() => {
    if (isOpen && sessions.length > 0 && !currentSessionId && messages.length === 0) {
      // Load the most recent session
      loadSession(sessions[0].id);
    }
  }, [isOpen, sessions, currentSessionId, messages.length, loadSession]);

  // Send message with streaming
  const sendMessage = async () => {
    if (!input.trim() || loading || streaming) return;

    const userMessage = input.trim();
    setInput("");

    // Ensure we have a session
    let sessionId = currentSessionId;
    if (!sessionId) {
      sessionId = await createSession();
      if (!sessionId) return;
    }

    // Add user message
    setMessages((prev) => [...prev, { role: "user", content: userMessage }]);
    setLoading(true);
    setStreaming(true);
    setStreamContent("");

    try {
      const token = localStorage.getItem("auth_token");
      const headers: HeadersInit = { "Content-Type": "application/json" };
      if (token) headers["Authorization"] = `Bearer ${token}`;

      // Build history (last 10 messages)
      const history = messages.slice(-10).map((m) => ({
        role: m.role,
        content: m.content,
      }));

      const response = await fetch("/api/ai/chat/stream", {
        method: "POST",
        headers,
        body: JSON.stringify({
          session_id: sessionId,
          message: userMessage,
          history,
        }),
      });

      if (!response.ok) {
        throw new Error("Failed to send message");
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      let accumulated = "";

      if (reader) {
        setLoading(false);

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          const chunk = decoder.decode(value);
          const lines = chunk.split("\n");

          for (const line of lines) {
            if (line.startsWith("data: ")) {
              try {
                const data = JSON.parse(line.slice(6));
                if (data.done) {
                  // Streaming complete
                  if (accumulated) {
                    setMessages((prev) => [
                      ...prev,
                      { role: "assistant", content: accumulated },
                    ]);
                  }
                  setStreamContent("");
                  setStreaming(false);
                } else if (data.content) {
                  accumulated += data.content;
                  setStreamContent(accumulated);
                } else if (data.error) {
                  throw new Error(data.error);
                }
              } catch {
                // Skip malformed JSON
              }
            }
          }
        }
      }
    } catch (err) {
      console.error("Stream error:", err);
      setMessages((prev) => prev.slice(0, -1)); // Remove user message on error
    } finally {
      setLoading(false);
      setStreaming(false);
      setStreamContent("");
      loadSessions(); // Refresh sessions to update title
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  // Resize handlers
  const startResize = useCallback(
    (e: ReactMouseEvent) => {
      e.preventDefault();
      setIsResizing(true);
      resizeRef.current = {
        startX: e.clientX,
        startY: e.clientY,
        startW: size.width,
        startH: size.height,
      };
    },
    [size]
  );

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isResizing || !resizeRef.current) return;

      const deltaX = resizeRef.current.startX - e.clientX;
      const deltaY = resizeRef.current.startY - e.clientY;

      setSize({
        width: Math.max(320, Math.min(800, resizeRef.current.startW + deltaX)),
        height: Math.max(400, Math.min(900, resizeRef.current.startH + deltaY)),
      });
    };

    const handleMouseUp = () => {
      setIsResizing(false);
      resizeRef.current = null;
    };

    if (isResizing) {
      document.addEventListener("mousemove", handleMouseMove);
      document.addEventListener("mouseup", handleMouseUp);
    }

    return () => {
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
    };
  }, [isResizing]);

  // New chat
  const handleNewChat = () => {
    setCurrentSessionId(null);
    setMessages([]);
    setView("chat");
  };

  const quickPrompts = [
    "Обзор состояния системы",
    "Топ активных пользователей",
    "Есть ли угрозы?",
    "Аномалии поведения",
  ];

  if (!isOpen) {
    return (
      <Button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 h-14 w-14 rounded-full shadow-lg z-50 bg-purple-600 hover:bg-purple-700"
        size="icon"
      >
        <MessageSquare className="h-6 w-6" />
      </Button>
    );
  }

  return (
    <div
      className={cn(
        "fixed z-50 bg-background border rounded-lg shadow-2xl flex flex-col overflow-hidden",
        isFullscreen
          ? "inset-4"
          : "bottom-6 right-6"
      )}
      style={
        isFullscreen
          ? undefined
          : { width: size.width, height: size.height }
      }
    >
      {/* Resize handle */}
      {!isFullscreen && (
        <div
          className="absolute top-0 left-0 w-4 h-4 cursor-nw-resize z-10"
          onMouseDown={startResize}
        >
          <div className="absolute top-1 left-1 w-2 h-2 border-t-2 border-l-2 border-muted-foreground/30" />
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b bg-muted/30">
        <div className="flex items-center gap-2">
          {view === "history" && (
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={() => setView("chat")}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
          )}
          <Sparkles className="h-5 w-5 text-purple-500" />
          <span className="font-semibold text-sm">
            {view === "history" ? "История чатов" : "AI Аналитик"}
          </span>
        </div>
        <div className="flex items-center gap-1">
          {view === "chat" && (
            <>
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                onClick={handleNewChat}
                title="Новый чат"
              >
                <Plus className="h-4 w-4" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                onClick={() => setView("history")}
                title="История"
              >
                <History className="h-4 w-4" />
              </Button>
            </>
          )}
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7"
            onClick={() => setIsFullscreen(!isFullscreen)}
          >
            {isFullscreen ? (
              <Minimize2 className="h-4 w-4" />
            ) : (
              <Maximize2 className="h-4 w-4" />
            )}
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7"
            onClick={() => setIsOpen(false)}
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Content */}
      {view === "history" ? (
        <div className="flex-1 overflow-hidden flex flex-col">
          <ScrollArea className="flex-1">
            <div className="p-2 space-y-1">
              {sessions.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground text-sm">
                  Нет сохранённых чатов
                </div>
              ) : (
                sessions.map((session) => (
                  <div
                    key={session.id}
                    className={cn(
                      "flex items-center justify-between p-2 rounded-md hover:bg-muted/50 cursor-pointer group",
                      currentSessionId === session.id && "bg-muted"
                    )}
                    onClick={() => loadSession(session.id)}
                  >
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium truncate">
                        {session.title}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {new Date(session.updated_at).toLocaleDateString("ru")}
                        {session.total_tokens > 0 && (
                          <span className="ml-2">
                            {session.total_tokens.toLocaleString()} токенов
                          </span>
                        )}
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 opacity-0 group-hover:opacity-100"
                      onClick={(e) => {
                        e.stopPropagation();
                        deleteSession(session.id);
                      }}
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                ))
              )}
            </div>
          </ScrollArea>
          {sessions.length > 0 && (
            <div className="p-2 border-t">
              <Button
                variant="destructive"
                size="sm"
                className="w-full"
                onClick={clearAllSessions}
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Очистить всё
              </Button>
            </div>
          )}
        </div>
      ) : (
        <>
          {/* Messages */}
          <div 
            ref={scrollRef}
            className="flex-1 px-4 overflow-y-auto scrollbar-thin scrollbar-thumb-muted-foreground/20 scrollbar-track-transparent"
          >
            {messages.length === 0 && !streamContent ? (
              <div className="text-center py-8 space-y-4">
                <Bot className="h-12 w-12 mx-auto text-muted-foreground opacity-50" />
                <div>
                  <p className="text-muted-foreground text-sm">
                    Задайте вопрос о данных системы
                  </p>
                </div>
                <div className="flex flex-wrap gap-2 justify-center">
                  {quickPrompts.map((prompt, i) => (
                    <Button
                      key={i}
                      variant="outline"
                      size="sm"
                      className="text-xs"
                      onClick={() => setInput(prompt)}
                    >
                      {prompt}
                    </Button>
                  ))}
                </div>
              </div>
            ) : (
              <div className="space-y-4 py-4">
                {messages.map((msg, i) => (
                  <div
                    key={i}
                    className={cn(
                      "flex gap-3",
                      msg.role === "user" ? "justify-end" : "justify-start"
                    )}
                  >
                    {msg.role === "assistant" && (
                      <div className="w-7 h-7 rounded-full bg-purple-500/10 flex items-center justify-center flex-shrink-0">
                        <Bot className="h-4 w-4 text-purple-500" />
                      </div>
                    )}
                    <div
                      className={cn(
                        "max-w-[85%] rounded-lg px-3 py-2 text-sm",
                        msg.role === "user"
                          ? "bg-primary text-primary-foreground"
                          : "bg-muted"
                      )}
                    >
                      {msg.role === "assistant" ? (
                        <div className="prose prose-sm dark:prose-invert max-w-none [&>*:first-child]:mt-0 [&>*:last-child]:mb-0">
                          <ReactMarkdown>{msg.content}</ReactMarkdown>
                        </div>
                      ) : (
                        <p>{msg.content}</p>
                      )}
                    </div>
                    {msg.role === "user" && (
                      <div className="w-7 h-7 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                        <User className="h-4 w-4 text-primary" />
                      </div>
                    )}
                  </div>
                ))}

                {/* Streaming message */}
                {(streaming || loading) && (
                  <div className="flex gap-3">
                    <div className="w-7 h-7 rounded-full bg-purple-500/10 flex items-center justify-center flex-shrink-0">
                      <Bot className="h-4 w-4 text-purple-500" />
                    </div>
                    <div className="bg-muted rounded-lg px-3 py-2 text-sm max-w-[85%]">
                      {streamContent ? (
                        <div className="prose prose-sm dark:prose-invert max-w-none [&>*:first-child]:mt-0 [&>*:last-child]:mb-0">
                          <ReactMarkdown>{streamContent}</ReactMarkdown>
                          <span className="inline-block w-1 h-4 bg-purple-500 animate-pulse ml-0.5" />
                        </div>
                      ) : (
                        <div className="flex items-center gap-2">
                          <Loader2 className="h-4 w-4 animate-spin" />
                          <span className="text-muted-foreground">Думаю...</span>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Input */}
          <div className="p-3 border-t">
            <div className="flex gap-2">
              <Textarea
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Спросите что-нибудь..."
                className="min-h-[44px] max-h-[120px] resize-none text-sm"
                disabled={loading || streaming}
              />
              <Button
                onClick={sendMessage}
                disabled={!input.trim() || loading || streaming}
                className="px-3 shrink-0"
                size="icon"
              >
                {loading || streaming ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Send className="h-4 w-4" />
                )}
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
