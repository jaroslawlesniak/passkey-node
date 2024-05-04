export type CreatePayload = {
  userId: number;
  credentialId: number;
  publicKey: string;
  counter: number;
  transports: string;
};

export type UpdatePayload = {
  userId?: number;
  credentialId?: number;
  publicKey?: string;
  counter?: number;
  transports?: string;
};
