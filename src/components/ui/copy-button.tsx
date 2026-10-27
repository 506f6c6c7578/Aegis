import * as React from "react"
import { Check, Copy } from "lucide-react"
import { Button } from "@/components/ui/button"
import { toast } from "@/components/ui/toast"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"

const confirmationDelayMs = 2000

function CopyButton({
  value,
  label,
  confirmation,
  ...props
}: Omit<React.ComponentProps<typeof Button>, "onClick" | "children"> & { value: string; label: string; confirmation: string }) {
  const [copied, setCopied] = React.useState(false)

  React.useEffect(() => {
    if (!copied) return
    const timer = setTimeout(() => setCopied(false), confirmationDelayMs)
    return () => clearTimeout(timer)
  }, [copied])

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      toast({ title: confirmation, variant: "success" })
    } catch {
      toast({ title: "Copie impossible", description: "Sélectionne le texte puis copie-le manuellement.", variant: "danger" })
    }
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant="outline"
          size="icon-sm"
          data-slot="copy-button"
          aria-label={`Copier : ${label}`}
          onClick={copy}
          {...props}
        >
          {copied ? <Check className="text-success" aria-hidden="true" /> : <Copy aria-hidden="true" />}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{copied ? "Copié" : "Copier"}</TooltipContent>
    </Tooltip>
  )
}

export { CopyButton }
