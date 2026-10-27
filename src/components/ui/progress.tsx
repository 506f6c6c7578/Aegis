import * as React from "react"
import { cn } from "cn"
import { Progress as ProgressPrimitive } from "radix-ui"

function Progress({
  className,
  value,
  max = 100,
  indicatorClassName,
  ...props
}: React.ComponentProps<typeof ProgressPrimitive.Root> & { indicatorClassName?: string }) {
  const ratio = value === null || value === undefined ? null : Math.min(Math.max(value / max, 0), 1)

  return (
    <ProgressPrimitive.Root
      data-slot="progress"
      value={value}
      max={max}
      className={cn("relative flex h-1.5 w-full items-center overflow-hidden rounded-full bg-muted", className)}
      {...props}
    >
      <ProgressPrimitive.Indicator data-slot="progress-indicator" asChild>
        <svg className="size-full" viewBox="0 0 100 1" preserveAspectRatio="none" aria-hidden="true">
          {ratio === null ? (
            <rect className={cn("animate-pulse fill-brand", indicatorClassName)} width="100" height="1"/>
          ) : ratio > 0 && (
            <rect className={cn("origin-left animate-grow-x fill-brand [transform-box:fill-box]", indicatorClassName)}
                  width={ratio * 100} height="1"/>
          )}
        </svg>
      </ProgressPrimitive.Indicator>
    </ProgressPrimitive.Root>
  )
}

export { Progress }
