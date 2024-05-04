import { uuid } from '@/lib/uuid';

import { prisma } from '../client';

export const getById = (id: number) =>
  prisma.user.findFirstOrThrow({
    where: { id }
  });

export const getByUserName = (userName: string) =>
  prisma.user.findFirstOrThrow({
    where: { userName }
  });

export const create = (userName: string) =>
  prisma.user.create({
    data: {
      token: uuid(),
      userName,
    }
  });
