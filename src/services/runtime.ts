import { AEGIS_DNS_SERVERS, AEGIS_SECRET } from "astro:env/server";
import { createTokenSigner } from "@/lib/crypto/signed-token";
import { systemConnector } from "@/lib/network/connector";
import { createAuditService } from "@/services/audits/service";
import { createControlledResolver, parseDnsServers } from "@/services/dns/resolver";
import { createVerificationService } from "@/services/verification/service";

const resolver = createControlledResolver(parseDnsServers(AEGIS_DNS_SERVERS));

export const verification = createVerificationService({ signer: createTokenSigner(AEGIS_SECRET), resolver });

export const audits = createAuditService({ verification, resolver, connector: systemConnector });
