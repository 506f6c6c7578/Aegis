import { CircleHelp } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Drawer, DrawerContent, DrawerDescription, DrawerHeader, DrawerTitle, DrawerTrigger } from "@/components/ui/drawer";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { useMediaQuery } from "@/hooks/use-media-query";

const steps = [
    "Ouvre l'interface de gestion DNS chez ton registraire ou ton hébergeur DNS (OVHcloud, Cloudflare, Gandi, etc.).",
    "Ajoute un enregistrement de type TXT.",
    "Dans le champ du nom (ou sous-domaine), colle le nom indiqué. Certains fournisseurs ajoutent le domaine automatiquement : saisis alors seulement _aegis-verify.",
    "Dans le champ de la valeur, colle le jeton exact, sans espace ni guillemets supplémentaires.",
    "Choisis une durée de vie (TTL) courte, par exemple 300 secondes, puis enregistre.",
    "Patiente une à quelques minutes puis lance la vérification. Tu pourras supprimer l'enregistrement une fois l'analyse terminée."
];

function HelpContent() {
    return (
        <ol className="grid list-decimal gap-3 px-4 pb-6 pl-9 text-[0.9375rem]">
            {steps.map((step) => <li key={step}>{step}</li>)}
        </ol>
    );
}

const title = "Créer l'enregistrement TXT";
const description = "La démarche est la même chez la plupart des fournisseurs DNS.";

export function DnsHelp() {
    const desktop = useMediaQuery("(min-width: 48rem)");
    const trigger = (
        <Button variant="ghost" size="sm">
            <CircleHelp aria-hidden="true"/>
            Comment créer cet enregistrement ?
        </Button>
    );

    return desktop ? (
        <Sheet>
            <SheetTrigger asChild>{trigger}</SheetTrigger>
            <SheetContent className="sm:max-w-md">
                <SheetHeader>
                    <SheetTitle>{title}</SheetTitle>
                    <SheetDescription>{description}</SheetDescription>
                </SheetHeader>
                <HelpContent/>
            </SheetContent>
        </Sheet>
    ) : (
        <Drawer>
            <DrawerTrigger asChild>{trigger}</DrawerTrigger>
            <DrawerContent>
                <DrawerHeader>
                    <DrawerTitle>{title}</DrawerTitle>
                    <DrawerDescription>{description}</DrawerDescription>
                </DrawerHeader>
                <div className="overflow-y-auto">
                    <HelpContent/>
                </div>
            </DrawerContent>
        </Drawer>
    );
}
