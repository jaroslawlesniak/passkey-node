import { uuid } from '@/lib/uuid';

import { prisma } from '../client';

export const getById = (id: number) =>
  prisma.user.findFirstOrThrow({
    where: { id }
  });

export const getByToken = (token: string) =>
  prisma.user.findFirstOrThrow({
    where: { token }
  });

export const getByEmail = (email: string) =>
  prisma.user.findFirstOrThrow({
    where: { email }
  });

export const create = (email: string) =>
  prisma.user.create({
    data: {
      token: uuid(),
      email,
    }
  });
