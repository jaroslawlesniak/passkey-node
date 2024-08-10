import { uuid } from "@/lib/uuid";

import { prisma } from "../client";
import type { CreatePayload, UpdatePayload } from "./types";

export const create = ({
  counter,
  publicKey,
  transports,
  userId,
  credentialId,
}: CreatePayload) =>
  prisma.credential.create({
    data: {
      token: uuid(),
      userId,
      counter,
      publicKey,
      credentialId,
      transports,
    },
  });

export const getById = (id: number) =>
  prisma.credential.findFirstOrThrow({
    where: { id },
  });

export const getByCredentialId = (credentialId: string) =>
  prisma.credential.findFirstOrThrow({
    where: { credentialId },
  });

export const update = (id: number, { counter }: UpdatePayload) =>
  prisma.credential.update({
    where: { id },
    data: { counter },
  });
