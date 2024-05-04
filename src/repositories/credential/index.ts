import { uuid } from "@/lib/uuid";

import type { CreatePayload, UpdatePayload } from "./types";

import { prisma } from "../client";

export const create = ({ counter, publicKey, transports, userId }: CreatePayload) =>
  prisma.credential.create({
    data: {
      token: uuid(),
      userId,
      counter,
      publicKey,
      transports,
    }
  })

export const getById = (id: number) =>
  prisma.credential.findFirstOrThrow({
    where: { id },
  });

export const update = (id: number, { counter }: UpdatePayload) =>
  prisma.credential.update({
    where: { id },
    data: { counter },
  });
