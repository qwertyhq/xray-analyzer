"use client";

import { useState, useRef, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import {
  Bot,
  Send,
  Loader2,
  User,
  Sparkles,
  AlertCircle,
  Trash2,
} from "lucide-react";
import ReactMarkdown from "react-markdown";

interface Message {
  role: "user" | "assistant";
  content: string;
  tokensUsed?: number;
}

interface AIChatProps {
  className?: string;
}

export function AIChat({ className }: AIChatProps) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [totalTokens, setTotalTokens] = useState(0);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  const sendMessage = async () => {
    if (!input.trim() || loading) return;

    const userMessage = input.trim();
    setInput("");
    setError(null);

    // Add user message
    setMessages((prev) => [...prev, { role: "user", content: userMessage }]);
    setLoading(true);

    try {
      const token = localStorage.getItem("auth_token");
      const headers: HeadersInit = { "Content-Type": "application/json" };
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }

      // Build history (last 10 messages for context)
      const history = messages.slice(-10).map((m) => ({
        role: m.role,
        content: m.content,
      }));

      const response = await fetch("/api/ai/chat", {
        method: "POST",
        headers,
        body: JSON.stringify({
          message: userMessage,
          history,
        }),
      });

      const data = await response.json();

      if (data.error) {
        setError(data.error);
        // Remove the user message if there was an error
        setMessages((prev) => prev.slice(0, -1));
      } else {
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: data.response,
            tokensUsed: data.tokens_used,
          },
        ]);
        setTotalTokens((prev) => prev + (data.tokens_used || 0));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to send message");
      // Remove the user message if there was an error
      setMessages((prev) => prev.slice(0, -1));
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const clearChat = () => {
    setMessages([]);
    setTotalTokens(0);
    setError(null);
  };

  const quickPrompts = [
    "Дай обзор состояния системы",
    "Кто самые активные пользователи?",
    "Какие угрозы были за последнее время?",
    "Есть ли аномалии в поведении пользователей?",
    "Покажи статистику по странам",
  ];

  return (
    <Card className={className}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-purple-500" />
            AI Аналитик
          </CardTitle>
          <div className="flex items-center gap-2">
            {totalTokens > 0 && (
              <Badge variant="outline" className="text-xs">
                {totalTokens.toLocaleString()} токенов
              </Badge>
            )}
            {messages.length > 0 && (
              <Button
                variant="ghost"
                size="sm"
                onClick={clearChat}
                className="h-8 px-2"
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Messages */}
        <ScrollArea className="h-[400px] pr-4" ref={scrollRef}>
          {messages.length === 0 ? (
            <div className="text-center py-8 space-y-4">
              <Bot className="h-12 w-12 mx-auto text-muted-foreground opacity-50" />
              <div>
                <p className="text-muted-foreground">
                  Задайте вопрос о данных системы
                </p>
                <p className="text-xs text-muted-foreground mt-1">
                  AI проанализирует пользователей, угрозы, аномалии и статистику
                </p>
              </div>
              {/* Quick prompts */}
              <div className="flex flex-wrap gap-2 justify-center pt-4">
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
            <div className="space-y-4">
              {messages.map((msg, i) => (
                <div
                  key={i}
                  className={`flex gap-3 ${
                    msg.role === "user" ? "justify-end" : "justify-start"
                  }`}
                >
                  {msg.role === "assistant" && (
                    <div className="w-8 h-8 rounded-full bg-purple-500/10 flex items-center justify-center flex-shrink-0">
                      <Bot className="h-4 w-4 text-purple-500" />
                    </div>
                  )}
                  <div
                    className={`max-w-[80%] rounded-lg px-4 py-2 ${
                      msg.role === "user"
                        ? "bg-primary text-primary-foreground"
                        : "bg-muted"
                    }`}
                  >
                    {msg.role === "assistant" ? (
                      <div className="prose prose-sm dark:prose-invert max-w-none">
                        <ReactMarkdown>{msg.content}</ReactMarkdown>
                      </div>
                    ) : (
                      <p className="text-sm">{msg.content}</p>
                    )}
                    {msg.tokensUsed && (
                      <p className="text-xs text-muted-foreground mt-1 opacity-50">
                        {msg.tokensUsed} токенов
                      </p>
                    )}
                  </div>
                  {msg.role === "user" && (
                    <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                      <User className="h-4 w-4 text-primary" />
                    </div>
                  )}
                </div>
              ))}
              {loading && (
                <div className="flex gap-3">
                  <div className="w-8 h-8 rounded-full bg-purple-500/10 flex items-center justify-center flex-shrink-0">
                    <Bot className="h-4 w-4 text-purple-500" />
                  </div>
                  <div className="bg-muted rounded-lg px-4 py-3">
                    <Loader2 className="h-4 w-4 animate-spin" />
                  </div>
                </div>
              )}
            </div>
          )}
        </ScrollArea>

        {/* Error */}
        {error && (
          <div className="flex items-center gap-2 text-destructive text-sm">
            <AlertCircle className="h-4 w-4" />
            {error}
          </div>
        )}

        {/* Input */}
        <div className="flex gap-2">
          <Textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Спросите о пользователях, угрозах, статистике..."
            className="min-h-[60px] resize-none"
            disabled={loading}
          />
          <Button
            onClick={sendMessage}
            disabled={!input.trim() || loading}
            className="px-3"
          >
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Send className="h-4 w-4" />
            )}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
