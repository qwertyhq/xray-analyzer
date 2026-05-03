"use client";

import { useEffect, useRef, useState } from "react";

interface AnimatedNumberProps {
  value: number;
  duration?: number;
  className?: string;
  formatFn?: (value: number) => string;
}

export function AnimatedNumber({ 
  value, 
  duration = 500, 
  className = "",
  formatFn = (v) => v.toLocaleString()
}: AnimatedNumberProps) {
  const [displayValue, setDisplayValue] = useState(value);
  const previousValue = useRef(value);
  const animationRef = useRef<number | null>(null);

  useEffect(() => {
    const startValue = previousValue.current;
    const endValue = value;
    const startTime = performance.now();

    const animate = (currentTime: number) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      
      // Easing function (easeOutCubic)
      const easeProgress = 1 - Math.pow(1 - progress, 3);
      
      const current = startValue + (endValue - startValue) * easeProgress;
      setDisplayValue(Math.round(current));

      if (progress < 1) {
        animationRef.current = requestAnimationFrame(animate);
      } else {
        previousValue.current = endValue;
      }
    };

    if (animationRef.current) {
      cancelAnimationFrame(animationRef.current);
    }

    if (startValue !== endValue) {
      animationRef.current = requestAnimationFrame(animate);
    } else {
      setDisplayValue(value);
    }

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [value, duration]);

  return (
    <span className={`transition-colors duration-300 ${className}`}>
      {formatFn(displayValue)}
    </span>
  );
}

// Component for bytes (traffic)
export function AnimatedBytes({
  value, 
  duration = 500,
  className = "" 
}: Omit<AnimatedNumberProps, 'formatFn'>) {
  const formatBytes = (bytes: number) => {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  return (
    <AnimatedNumber 
      value={value} 
      duration={duration} 
      className={className}
      formatFn={formatBytes}
    />
  );
}

// Component for percentages
export function AnimatedPercent({ 
  value, 
  duration = 500,
  className = "",
  decimals = 1
}: Omit<AnimatedNumberProps, 'formatFn'> & { decimals?: number }) {
  return (
    <AnimatedNumber 
      value={value} 
      duration={duration} 
      className={className}
      formatFn={(v) => v.toFixed(decimals) + "%"}
    />
  );
}
