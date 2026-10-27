import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { CircleCheck, Info, OctagonAlert, XIcon } from "lucide-react"
import { Toast as ToastPrimitive } from "radix-ui"
import { useHydrated } from "@/hooks/use-hydrated"

const toastVariants = cva(
  "pointer-events-auto grid grid-cols-[auto_1fr_auto] items-start gap-x-3 gap-y-0.5 rounded-xl border bg-popover p-4 text-sm text-popover-foreground shadow-lg data-open:animate-in data-open:fade-in-0 data-open:slide-in-from-bottom-4 data-closed:animate-out data-closed:fade-out-0 data-[swipe=end]:animate-out data-[swipe=end]:fade-out-0 [&>svg]:mt-0.5 [&>svg]:size-4",
  {
    variants: {
      variant: {
        default: "[&>svg]:text-brand",
        success: "[&>svg]:text-success",
        danger: "[&>svg]:text-danger",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

type ToastVariant = NonNullable<VariantProps<typeof toastVariants>["variant"]>

interface ToastMessage {
  id: number
  title: string
  description?: string
  variant: ToastVariant
}

const toastIcons = {
  default: Info,
  success: CircleCheck,
  danger: OctagonAlert,
} as const satisfies Record<ToastVariant, React.ComponentType>

const maxVisibleToasts = 3
const toastDurationMs = 5000
const listeners = new Set<() => void>()
const emptyToasts: readonly ToastMessage[] = []
let toasts: readonly ToastMessage[] = emptyToasts
let nextToastId = 0

function emit(next: readonly ToastMessage[]) {
  toasts = next
  for (const listener of listeners) listener()
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

function toast({ title, description, variant = "default" }: Omit<ToastMessage, "id" | "variant"> & { variant?: ToastVariant }) {
  nextToastId += 1
  emit([...toasts, { id: nextToastId, title, description, variant }].slice(-maxVisibleToasts))
}

function dismiss(id: number) {
  emit(toasts.filter((item) => item.id !== id))
}

function Toaster() {
  const hydrated = useHydrated()
  const items = React.useSyncExternalStore(subscribe, () => toasts, () => emptyToasts)

  if (!hydrated) return null

  return (
    <ToastPrimitive.Provider label="Notification" swipeDirection="right" duration={toastDurationMs}>
      {items.map(({ id, title, description, variant }) => {
        const Icon = toastIcons[variant]
        return (
          <ToastPrimitive.Root
            key={id}
            data-slot="toast"
            className={toastVariants({ variant })}
            onOpenChange={(open) => {
              if (!open) dismiss(id)
            }}
          >
            <Icon aria-hidden="true" />
            <ToastPrimitive.Title className="font-semibold text-foreground">{title}</ToastPrimitive.Title>
            <ToastPrimitive.Close
              className="row-span-2 rounded-md p-0.5 text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
              aria-label="Fermer la notification"
            >
              <XIcon className="size-4" aria-hidden="true" />
            </ToastPrimitive.Close>
            {description && (
              <ToastPrimitive.Description className="col-start-2 text-muted-foreground">{description}</ToastPrimitive.Description>
            )}
          </ToastPrimitive.Root>
        )
      })}
      <ToastPrimitive.Viewport
        data-slot="toast-viewport"
        className="pointer-events-none fixed right-0 bottom-0 z-[100] flex w-full flex-col gap-2 p-4 outline-none sm:max-w-sm"
      />
    </ToastPrimitive.Provider>
  )
}

export { Toaster, toast }
